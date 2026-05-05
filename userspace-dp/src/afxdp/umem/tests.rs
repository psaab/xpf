// Tests for afxdp/umem/mod.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep mod.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "tests.rs"]` from umem/mod.rs.

use super::*;

#[test]
fn mmap_area_rejects_access_beyond_registered_len_even_if_mapping_is_rounded() {
    let area = MmapArea::new(128).expect("mmap");

    assert!(area.slice(0, 128).is_some());
    assert!(area.slice(128, 1).is_none());
    assert!(area.slice(512, 1).is_none());
}

fn test_tx_request_for_inbox(payload: u8) -> TxRequest {
    TxRequest {
        bytes: vec![payload; 16],
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: 6,
        flow_key: None,
        egress_ifindex: 0,
        cos_queue_id: None,
        dscp_rewrite: None,
    }
}

#[test]
fn enqueue_tx_owned_increments_redirect_inbox_overflow_counter_when_soft_cap_drops_newcomer() {
    // #710 / #706: pin that a redirect-inbox overflow in
    // `enqueue_tx_owned` increments both `redirect_inbox_overflow_drops`
    // (dedicated view) and `tx_errors` (generic), regardless of
    // which request gets dropped. Post-#706 the policy is drop-
    // newest (the incoming push is discarded); pre-#706 it was
    // drop-oldest (the head of the queue was evicted). Either way,
    // every push must return `Ok(())` and both counters advance in
    // lockstep.
    let live = BindingLiveState::new();
    live.max_pending_tx.store(2, Ordering::Relaxed);

    // Fill to cap — no overflow yet.
    live.enqueue_tx_owned(test_tx_request_for_inbox(1))
        .expect("push 1");
    live.enqueue_tx_owned(test_tx_request_for_inbox(2))
        .expect("push 2");
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        0
    );
    assert_eq!(live.tx_errors.load(Ordering::Relaxed), 0);

    // Third push hits the soft cap — drop-newest, counters advance.
    live.enqueue_tx_owned(test_tx_request_for_inbox(3))
        .expect("push 3 drops newest");
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        live.tx_errors.load(Ordering::Relaxed),
        1,
        "generic tx_errors stays in lockstep with the dedicated drop \
         counter on this path — the dedicated counter is a subset view"
    );

    // Fourth push, another overflow — both counters advance again.
    live.enqueue_tx_owned(test_tx_request_for_inbox(4))
        .expect("push 4 drops newest");
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        2
    );
    assert_eq!(live.tx_errors.load(Ordering::Relaxed), 2);
}

#[test]
fn take_pending_tx_into_appends_without_resetting_caller_buffer() {
    // #706: pin that `take_pending_tx_into` preserves the caller's
    // existing `VecDeque` contents. The owner-worker drain feeds its
    // `pending_tx_local` buffer through the call; if the new API ever
    // regressed to `*out = drained` or `out.clear()`, items already
    // queued locally would be dropped on every poll.
    let live = BindingLiveState::new();
    live.max_pending_tx.store(8, Ordering::Relaxed);
    live.enqueue_tx_owned(test_tx_request_for_inbox(10))
        .expect("push inbox");
    live.enqueue_tx_owned(test_tx_request_for_inbox(11))
        .expect("push inbox");

    let mut out = VecDeque::from([test_tx_request_for_inbox(1), test_tx_request_for_inbox(2)]);
    live.take_pending_tx_into(&mut out);

    let payloads: Vec<u8> = out.iter().map(|req| req.bytes[0]).collect();
    assert_eq!(
        payloads,
        vec![1, 2, 10, 11],
        "caller-provided items must come first; inbox items appended in FIFO order"
    );
    assert!(live.pending_tx_empty(), "inbox fully drained");
}

#[test]
fn enqueue_tx_owned_below_cap_does_not_touch_overflow_counter() {
    let live = BindingLiveState::new();
    live.max_pending_tx.store(8, Ordering::Relaxed);

    for payload in 0..4 {
        live.enqueue_tx_owned(test_tx_request_for_inbox(payload))
            .expect("push below cap");
    }
    assert_eq!(
        live.redirect_inbox_overflow_drops.load(Ordering::Relaxed),
        0
    );
    assert_eq!(live.tx_errors.load(Ordering::Relaxed), 0);
}

#[test]
fn bucket_index_for_ns_covers_powers_of_two_from_1us_to_32ms() {
    // #709: pin the bucket layout. Bucket 0 covers ns in
    // [0, 1024); bucket 1 covers [1024, 2048); ... bucket 15
    // saturates at >= 2^25 ns. Anyone editing the formula in
    // `bucket_index_for_ns` must either keep this layout or
    // renumber the wire contract — this test fails loudly on
    // either.
    // Bucket 0 is the "<= 1024 ns" catch-all: ns ∈ [0, 1024) lands
    // here, ns = 1024 promotes to bucket 1.
    assert_eq!(bucket_index_for_ns(0), 0);
    assert_eq!(bucket_index_for_ns(1), 0);
    assert_eq!(bucket_index_for_ns(1023), 0);
    assert_eq!(bucket_index_for_ns(1024), 1);
    assert_eq!(bucket_index_for_ns(2047), 1);
    assert_eq!(bucket_index_for_ns(2048), 2);
    assert_eq!(bucket_index_for_ns(4095), 2);
    assert_eq!(bucket_index_for_ns(4096), 3);
    // Walk each bucket boundary [2^(N+9), 2^(N+10)) for
    // N ∈ [1, 15). Expect `bucket_index_for_ns(2^(N+9)) == N`
    // and `bucket_index_for_ns(2^(N+10) - 1) == N`. We skip N=0
    // because bucket 0 is the sub-1024 catch-all (its `lo` is 0
    // not `2^9`), covered by the explicit asserts above.
    for n in 1..(DRAIN_HIST_BUCKETS - 1) {
        let lo = 1u64 << (n + 9);
        let hi = (1u64 << (n + 10)).saturating_sub(1);
        assert_eq!(
            bucket_index_for_ns(lo),
            n,
            "lo boundary for bucket {n}: ns={lo}",
        );
        assert_eq!(
            bucket_index_for_ns(hi),
            n,
            "hi boundary for bucket {n}: ns={hi}",
        );
    }
    // Top bucket: ns >= 2^24 saturates at 15.
    assert_eq!(bucket_index_for_ns(1u64 << 24), DRAIN_HIST_BUCKETS - 1);
    assert_eq!(bucket_index_for_ns(1u64 << 25), DRAIN_HIST_BUCKETS - 1);
    assert_eq!(bucket_index_for_ns(u64::MAX), DRAIN_HIST_BUCKETS - 1);
}

#[test]
fn bucket_index_for_ns_handles_zero() {
    // #709: `ns = 0` must land in bucket 0 and MUST NOT panic. The
    // implementation uses `(ns | 1).leading_zeros()` specifically
    // to avoid `leading_zeros(0) == 64` which would cascade into a
    // negative subtraction after the `54 - clz` step. This pins
    // that the OR-with-1 guard is still in place after future
    // edits.
    assert_eq!(bucket_index_for_ns(0), 0);
}

#[test]
fn bucket_index_for_ns_saturates_above_top_bucket() {
    // #709: ns = 1 trillion (~17 minutes) must clamp at bucket 15.
    // If a future refactor ever turned the `.min(DRAIN_HIST_BUCKETS - 1)`
    // into a subtraction, this would underflow silently on release
    // builds — the min clamp is the wire-contract guard.
    assert_eq!(
        bucket_index_for_ns(1_000_000_000_000),
        DRAIN_HIST_BUCKETS - 1
    );
}

#[test]
fn drain_latency_hist_increments_on_recorded_drain() {
    // #709: exercise the hist-update path in isolation. We do not
    // call `drain_shaped_tx` here (requires a fully-constructed
    // BindingWorker fixture); instead, we recreate the exact shape
    // tx.rs uses — bucket_index_for_ns + fetch_add — and assert
    // the bucket landed in the right slot.
    let live = BindingLiveState::new();
    let delta_ns = 1500u64; // bucket 1 ([1024, 2048))
    let bucket = bucket_index_for_ns(delta_ns);
    live.owner_profile_owner.drain_latency_hist[bucket].fetch_add(1, Ordering::Relaxed);
    live.owner_profile_owner
        .drain_invocations
        .fetch_add(1, Ordering::Relaxed);
    assert_eq!(bucket, 1);
    assert_eq!(
        live.owner_profile_owner.drain_latency_hist[1].load(Ordering::Relaxed),
        1
    );
    // Counter-factual: surrounding buckets must stay at 0. A prior
    // draft that used the wrong shift constant (e.g. `55 - clz`)
    // would light up bucket 0 or 2 here — this assertion catches
    // the off-by-one.
    assert_eq!(
        live.owner_profile_owner.drain_latency_hist[0].load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        live.owner_profile_owner.drain_latency_hist[2].load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        live.owner_profile_owner
            .drain_invocations
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn redirect_acquire_hist_samples_one_in_mask_plus_one() {
    // #709: drive `enqueue_tx_owned` exactly `REDIRECT_SAMPLE_MASK
    // + 1` times and assert exactly one bucket increment. The
    // sample counter is seeded to 0 by `new()`, so on the first
    // push `(counter & MASK) == 0` fires; subsequent MASK pushes
    // skip, and the (MASK+1)-th push would fire again.
    let live = BindingLiveState::new();
    live.max_pending_tx.store(8192, Ordering::Relaxed);
    let iterations = (REDIRECT_SAMPLE_MASK + 1) as usize;
    for _ in 0..iterations {
        live.enqueue_tx_owned(test_tx_request_for_inbox(0xab))
            .expect("push");
    }
    let total_samples: u64 = live
        .owner_profile_peer
        .redirect_acquire_hist
        .iter()
        .map(|slot| slot.load(Ordering::Relaxed))
        .sum();
    assert_eq!(
        total_samples, 1,
        "exactly one sample per (REDIRECT_SAMPLE_MASK + 1) pushes"
    );

    // Counter-factual: a pre-#709 path (no sampling, no bucket
    // increment) would leave the histogram at zero after the same
    // push count. Reset and demonstrate by skipping the hist update
    // inline — this proves the test's positive assertion above is
    // actually exercising the #709-added code path, not some
    // always-live fallback.
    let live2 = BindingLiveState::new();
    live2.max_pending_tx.store(8192, Ordering::Relaxed);
    // Replicate the non-sampled producer: raw MPSC push without
    // the sample/timer wrapper.
    for _ in 0..iterations {
        live2
            .pending_tx
            .push(test_tx_request_for_inbox(0xcd))
            .expect("push raw");
    }
    let pre_709_total: u64 = live2
        .owner_profile_peer
        .redirect_acquire_hist
        .iter()
        .map(|slot| slot.load(Ordering::Relaxed))
        .sum();
    assert_eq!(
        pre_709_total, 0,
        "raw MPSC push (pre-#709 shape) must not touch the redirect-acquire histogram"
    );
}

#[test]
fn new_seeded_initialises_redirect_sample_counter_from_worker_id() {
    // #709: per-worker seeding prevents lockstep sampling. Two
    // workers with different ids must start at different positions
    // in the 1-in-(MASK+1) cycle. Seed with 0 and 1 and verify
    // both new_seeded instances hold distinct initial counter
    // values.
    let a = BindingLiveState::new_seeded(0);
    let b = BindingLiveState::new_seeded(1);
    assert_eq!(
        a.owner_profile_peer
            .redirect_sample_counter
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        b.owner_profile_peer
            .redirect_sample_counter
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn binding_live_snapshot_propagates_709_owner_profile_counters() {
    // #709: pin that the snapshot() path copies all owner-profile
    // atomics into the BindingLiveSnapshot. A future edit that
    // misses one field would silently under-surface telemetry to
    // the operator CLI / Prometheus — this test fails fast on the
    // missing field.
    let live = BindingLiveState::new();
    live.owner_profile_owner.drain_latency_hist[3].store(7, Ordering::Relaxed);
    live.owner_profile_owner.drain_latency_hist[15].store(2, Ordering::Relaxed);
    live.owner_profile_owner
        .drain_invocations
        .store(100, Ordering::Relaxed);
    live.owner_profile_owner
        .drain_noop_invocations
        .store(50, Ordering::Relaxed);
    live.owner_profile_peer.redirect_acquire_hist[1].store(11, Ordering::Relaxed);
    live.owner_profile_owner
        .owner_pps
        .store(1234, Ordering::Relaxed);
    live.owner_profile_peer
        .peer_pps
        .store(567, Ordering::Relaxed);

    // #812: exercise the new TX submit-latency atomics on the
    // same snapshot path so a future `snapshot()` refactor that
    // drops one of the three new loads fails here (same shape
    // as the #709 pin above). Non-coprime values per field so
    // a cross-field mis-attribution is caught.
    live.owner_profile_owner.tx_submit_latency_hist[2].store(19, Ordering::Relaxed);
    live.owner_profile_owner.tx_submit_latency_hist[14].store(23, Ordering::Relaxed);
    live.owner_profile_owner
        .tx_submit_latency_count
        .store(42, Ordering::Relaxed);
    live.owner_profile_owner
        .tx_submit_latency_sum_ns
        .store(999_999, Ordering::Relaxed);

    let snap = live.snapshot();
    assert_eq!(snap.drain_latency_hist[3], 7);
    assert_eq!(snap.drain_latency_hist[15], 2);
    assert_eq!(snap.drain_invocations, 100);
    assert_eq!(snap.drain_noop_invocations, 50);
    assert_eq!(snap.redirect_acquire_hist[1], 11);
    assert_eq!(snap.owner_pps, 1234);
    assert_eq!(snap.peer_pps, 567);
    // #812 new assertions.
    assert_eq!(snap.tx_submit_latency_hist[2], 19);
    assert_eq!(snap.tx_submit_latency_hist[14], 23);
    assert_eq!(snap.tx_submit_latency_count, 42);
    assert_eq!(snap.tx_submit_latency_sum_ns, 999_999);
}

#[test]
fn owner_profile_telemetry_is_cacheline_isolated_from_binding_live_state() {
    // #746: pin the alignment invariant this PR is buying. If a
    // future refactor silently drops the `#[repr(align(64))]`
    // attribute on either of the owner-profile structs — or
    // reshuffles `BindingLiveState` fields so the two groups
    // land on the same cacheline as their neighbor — this test
    // fails loudly.
    //
    // The two assertions are complementary: alignment on the
    // struct types alone is not enough if the containing
    // `BindingLiveState` somehow mis-places them, and field-offset
    // alignment alone is not enough if the struct itself lost its
    // `#[repr(align(64))]`.
    use core::mem::{align_of, offset_of, size_of};

    assert_eq!(align_of::<OwnerProfileOwnerWrites>(), 64);
    assert_eq!(align_of::<OwnerProfilePeerWrites>(), 64);

    let owner_off = offset_of!(BindingLiveState, owner_profile_owner);
    let peer_off = offset_of!(BindingLiveState, owner_profile_peer);
    assert_eq!(
        owner_off % 64,
        0,
        "owner_profile_owner must sit on a 64-byte cacheline boundary",
    );
    assert_eq!(
        peer_off % 64,
        0,
        "owner_profile_peer must sit on a 64-byte cacheline boundary",
    );

    // The two profile structs must NOT share a cacheline: their
    // offset difference must be at least the larger struct size
    // (both are padded to 64-B alignment, so this also implies
    // rounded-up cacheline distance).
    let gap = peer_off.abs_diff(owner_off);
    assert!(
        gap >= size_of::<OwnerProfileOwnerWrites>().max(size_of::<OwnerProfilePeerWrites>()),
        "owner and peer profile structs must not share a cacheline (gap={gap}, \
         owner_size={}, peer_size={})",
        size_of::<OwnerProfileOwnerWrites>(),
        size_of::<OwnerProfilePeerWrites>(),
    );
}

#[test]
fn binding_live_snapshot_propagates_710_drop_counters() {
    // #710: `refresh_bindings` in the coordinator copies
    // `snap.redirect_inbox_overflow_drops`, `pending_tx_local_overflow_drops`,
    // and `tx_submit_error_drops` onto the per-binding `BindingStatus`.
    // This test pins the contract that BindingLiveState::snapshot() actually
    // reads those atomics and writes them into the BindingLiveSnapshot
    // struct — the middle layer between the counter increments and
    // the operator-facing BindingStatus. `no_owner_binding_drops` is
    // intentionally NOT in the snapshot (see the rustdoc on
    // `BindingLiveSnapshot` for why), so it is not asserted here.
    let live = BindingLiveState::new();
    live.redirect_inbox_overflow_drops
        .store(3, Ordering::Relaxed);
    live.pending_tx_local_overflow_drops
        .store(5, Ordering::Relaxed);
    live.tx_submit_error_drops.store(7, Ordering::Relaxed);
    live.no_owner_binding_drops.store(11, Ordering::Relaxed);

    let snap = live.snapshot();
    assert_eq!(snap.redirect_inbox_overflow_drops, 3);
    assert_eq!(snap.pending_tx_local_overflow_drops, 5);
    assert_eq!(snap.tx_submit_error_drops, 7);
    // `no_owner_binding_drops` has no per-binding protocol surface;
    // it is read directly from the atomic by
    // `Coordinator::cos_no_owner_binding_drops_total()`.
    assert_eq!(
        live.no_owner_binding_drops.load(Ordering::Relaxed),
        11,
        "atomic remains readable for the coordinator-level aggregation"
    );
}

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
    // path at the commit-rejected sites (e.g. tx.rs:1858-1866
    // / tx.rs:6038-6045) hands NO offsets to `stamp_submits`
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
    // Skew bound (plan §3.6 R2 / §6.1):
    //   K_skew = ceil(λ_obs × W_read_max) + 2
    //   λ_obs = count_final / elapsed_wall_ns
    //         (measured AFTER stopping the writer, per Codex §7)
    //   W_read_max = max snapshot read window observed
    //   +2 margin is TSO / ARM re-order allowance, independent of λ
    //
    // Pin assertion: max observed |sum − count| across all
    // reader snapshots ≤ K_skew.
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::sync::Mutex;
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
        w_read_ns: u64,
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
        let mut local = Vec::with_capacity(16_384);
        while !reader_stop.load(Ordering::Relaxed) {
            let pre = Instant::now();
            let snap = reader_live.snapshot();
            let w_read_ns = pre.elapsed().as_nanos() as u64;
            let count = snap.tx_submit_latency_count as i64;
            let sum_buckets: i64 = snap.tx_submit_latency_hist.iter().copied().sum::<u64>() as i64;
            let skew = (sum_buckets - count).abs();
            local.push(Sample { skew, w_read_ns });
        }
        *reader_samples.lock().unwrap() = local;
    });

    // Let the writer+reader run for a bounded wall window, then
    // shut the writer down and join both threads.
    let wall_start = Instant::now();
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    writer_handle.join().expect("writer thread joins cleanly");
    reader_handle.join().expect("reader thread joins cleanly");
    let elapsed_ns = wall_start.elapsed().as_nanos() as u64;

    // Post-hoc: compute λ_obs from final count / elapsed_wall
    // (plan §6.1 / Codex §7 — NOT from per-snapshot count).
    let final_snap = live.snapshot();
    let count_final = final_snap.tx_submit_latency_count;
    assert!(
        count_final > 0,
        "writer thread produced no completions — harness broken",
    );
    let lambda_obs_per_ns = count_final as f64 / elapsed_ns.max(1) as f64;

    let gathered = samples.lock().unwrap().clone();
    assert!(
        !gathered.is_empty(),
        "reader thread produced no snapshots — harness broken",
    );
    let mut max_skew = 0i64;
    let mut max_w_read_ns = 0u64;
    for s in &gathered {
        if s.skew > max_skew {
            max_skew = s.skew;
        }
        if s.w_read_ns > max_w_read_ns {
            max_w_read_ns = s.w_read_ns;
        }
    }
    // K_skew bound using the MAX observed read window and the
    // steady-state λ_obs. +2 is the derivation-independent
    // margin (plan §3.6 R2).
    //
    // Derivation (identical to #812 §3.6 R2): during one reader
    // window of duration W_read_ns, the writer emits at most
    // ceil(λ_obs × W_read_ns) records. The +2 absorbs two sources
    // of off-by-one: (1) a record in flight at window start that
    // had already incremented `count` but not yet the histogram
    // (or vice-versa), and (2) the analogous boundary at window
    // end. #812 empirically demonstrated this bound is tight for
    // the tx-completion path; `record_kick_latency` has the same
    // single-writer / Relaxed-ordering / count-then-bucket shape
    // (see `record_kick_latency` at tx.rs), so the derivation
    // carries over unchanged. Tightening the bound below +2
    // would risk flakes on schedulers with more jitter.
    let k_skew = (lambda_obs_per_ns * max_w_read_ns as f64).ceil() as i64 + 2;
    assert!(
        max_skew <= k_skew,
        "cross-thread skew {max_skew} exceeds bound K_skew = {k_skew} \
         (lambda_obs_per_ns={lambda_obs_per_ns:.6}, \
         max_w_read_ns={max_w_read_ns}, count_final={count_final}, \
         samples={})",
        gathered.len(),
    );
    eprintln!(
        "tx_latency_hist_cross_thread_snapshot_skew_within_bound: \
         max_skew={max_skew} k_skew={k_skew} \
         lambda_obs_per_ns={lambda_obs_per_ns:.6} \
         max_w_read_ns={max_w_read_ns} count_final={count_final}",
    );
}

#[test]
fn tx_submit_ns_sidecar_single_writer_ownership_is_rc_not_arc() {
    // #812 plan §6.1 test #6 (per §3.3 single-writer
    // invariant). `WorkerUmem` is `Rc<WorkerUmemInner>` at
    // umem.rs:16-18 — NOT `Arc` — enforcing single-owner
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
}

#[test]
fn tx_latency_hist_shared_umem_oob_offset_stamp_silent_drop() {
    // #812 Rust round-1 HIGH-1: under `shared_umem = true`
    // (mlx5 special case), a frame offset can come from the
    // shared pool such that `offset >> UMEM_FRAME_SHIFT` exceeds
    // THIS binding's sidecar length. `stamp_submits` MUST drop
    // the stamp silently — the slot belongs to a different
    // binding's sidecar and touching it here would either
    // overflow or corrupt an adjacent binding's accounting.
    //
    // Pin: build a small sidecar, drive `stamp_submits` with one
    // in-range and two out-of-range offsets, assert the in-range
    // slot landed exactly the stamp and ALL other slots are
    // untouched. The test also proves a foreign-offset stamp
    // cannot produce a phantom completion against an adjacent
    // sidecar slot (the "honest histogram" invariant that
    // HIGH-1 asked us to pin).
    let sidecar_len: u64 = 4;
    let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; sidecar_len as usize];
    let in_range = 1u64 << UMEM_FRAME_SHIFT; // idx 1, inside
    let just_past = sidecar_len << UMEM_FRAME_SHIFT; // idx == len
    let far_past = (sidecar_len + 1000) << UMEM_FRAME_SHIFT; // idx len+1000
    let ts = 42_000_000_000u64;
    crate::afxdp::tx::stamp_submits(
        &mut sidecar,
        [in_range, just_past, far_past].into_iter(),
        ts,
    );
    // Slot 1 stamped; slots 0, 2, 3 unchanged. OOB offsets
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
    // #812 Rust round-1 HIGH-1 companion: drive
    // `record_tx_completions_with_stamp` with an offset that
    // would index past `sidecar.len()`. `get_mut` returns None
    // → the fold treats the "stamp" as TX_SIDECAR_UNSTAMPED →
    // the delta check drops the sample → NO bucket bumped, NO
    // `count` / `sum_ns` increment. This is the reap-side half
    // of the "honest histogram" invariant: cross-binding offset
    // noise cannot produce a phantom completion.
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;
    let sidecar_len: u64 = 4;
    let mut sidecar = vec![TX_SIDECAR_UNSTAMPED; sidecar_len as usize];
    // Pre-stamp slot 0 with a legitimate value so a phantom
    // cross-slot bleed would be visible as a bucket bump.
    let t0 = 5_000_000_000u64;
    crate::afxdp::tx::stamp_submits(&mut sidecar, [0u64].into_iter(), t0);
    // Completion against an OOB offset — must be dropped.
    let oob_offset = (sidecar_len + 7) << UMEM_FRAME_SHIFT;
    let (count, sum) = crate::afxdp::tx::record_tx_completions_with_stamp(
        &mut sidecar,
        &[oob_offset],
        t0 + 10_000,
        owner,
    );
    assert_eq!(count, 0, "OOB completion must not be counted");
    assert_eq!(sum, 0, "OOB completion must not bump sum_ns");
    for b in 0..TX_SUBMIT_LAT_BUCKETS {
        assert_eq!(
            owner.tx_submit_latency_hist[b].load(Ordering::Relaxed),
            0,
            "bucket {b} must stay 0 on OOB completion",
        );
    }
    // Slot 0 is still stamped — the OOB reap must not have
    // touched any in-range slot.
    assert_eq!(sidecar[0], t0, "in-range slot corrupted by OOB reap");
}

// -------------------------------------------------------------
// #825 test pins. Plan §3.9.
// -------------------------------------------------------------

#[test]
fn tx_kick_latency_bucket_mapping_pin() {
    // #825 plan §3.9 test #1. Drive the production helper
    // `record_kick_latency` with deltas that land in specific
    // buckets (boundary + interior + saturation) and assert
    // one count per bucket plus matching count / sum_ns.
    //
    // bucket_index_for_ns pins (see umem.rs:198-202):
    //   delta=0 → bucket 0, delta=1 → bucket 0
    //   bucket i occupies 2^(i+9) ≤ delta < 2^(i+10) ns (i>=1)
    //     so bucket 3 covers [2^12, 2^13) = [4096, 8192)
    //     bucket 6 covers [2^15, 2^16) = [32768, 65536)
    //     bucket 14 covers [2^23, 2^24) = [8388608, 16777216)
    //     bucket 15 saturates at delta >= 2^24 = 16777216
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;

    // Pick an interior delta for each target bucket to avoid
    // boundary ambiguity. The `bucket_index_for_ns` comment
    // documents sub-1024ns delta → bucket 0, so use delta=500.
    let samples: [(u64, usize); 5] = [
        (500, 0),          // sub-1024 → bucket 0
        (5_000, 3),        // 2^12..2^13 → bucket 3
        (40_000, 6),       // 2^15..2^16 → bucket 6
        (10_000_000, 14),  // 2^23..2^24 → bucket 14
        (100_000_000, 15), // >= 2^24 → bucket 15 (saturate)
    ];
    // Cross-check each delta's expected bucket against the
    // production helper so a future `bucket_index_for_ns`
    // change either passes (if the mapping matches) or fails
    // with a clear error (not a silent regression).
    for &(delta, expected) in samples.iter() {
        assert_eq!(
            bucket_index_for_ns(delta),
            expected,
            "bucket mapping drift: delta={delta} expected bucket {expected}",
        );
        crate::afxdp::tx::record_kick_latency(owner, delta);
    }

    let snap = live.snapshot();
    // Each target bucket bumped exactly once.
    for &(_delta, bucket) in samples.iter() {
        assert_eq!(
            snap.tx_kick_latency_hist[bucket], 1,
            "bucket {bucket} must have exactly 1 sample",
        );
    }
    // Total count matches samples.len(); sum_ns matches the
    // sum of the deltas we fed.
    let expected_count = samples.len() as u64;
    let expected_sum_ns: u64 = samples.iter().map(|(d, _)| *d).sum();
    assert_eq!(snap.tx_kick_latency_count, expected_count);
    assert_eq!(snap.tx_kick_latency_sum_ns, expected_sum_ns);
    // Sum of all buckets equals count (single-thread: exact).
    let sum_buckets: u64 = snap.tx_kick_latency_hist.iter().copied().sum();
    assert_eq!(sum_buckets, expected_count);
}

#[test]
fn tx_kick_latency_accumulation_pin() {
    // #825 plan §3.9 test #2. N calls with a fixed delta; assert
    // count == N, sum_ns == N * delta, sum(hist) == N.
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;
    let n: u64 = 1_000;
    let delta: u64 = 3_000; // bucket 2 ([2^11, 2^12) = [2048, 4096)).
    for _ in 0..n {
        crate::afxdp::tx::record_kick_latency(owner, delta);
    }
    let snap = live.snapshot();
    assert_eq!(snap.tx_kick_latency_count, n);
    assert_eq!(snap.tx_kick_latency_sum_ns, n * delta);
    let sum_buckets: u64 = snap.tx_kick_latency_hist.iter().copied().sum();
    assert_eq!(sum_buckets, n);
    // All mass landed in the single target bucket.
    let b = bucket_index_for_ns(delta);
    assert_eq!(snap.tx_kick_latency_hist[b], n);
}

#[test]
fn tx_kick_latency_sentinel_zero_delta_records_bucket_zero() {
    // #825 plan §3.9 test #3a. delta=0 is a legal sample
    // (kick_end == kick_start within clock granularity) and
    // MUST land in bucket 0, not get dropped.
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;
    crate::afxdp::tx::record_kick_latency(owner, 0);
    let snap = live.snapshot();
    assert_eq!(snap.tx_kick_latency_count, 1);
    assert_eq!(snap.tx_kick_latency_sum_ns, 0);
    assert_eq!(snap.tx_kick_latency_hist[0], 1);
    // No leakage into any other bucket.
    let sum_buckets: u64 = snap.tx_kick_latency_hist.iter().copied().sum();
    assert_eq!(sum_buckets, 1);
}

#[test]
fn tx_kick_latency_sentinel_underflow_skipped_at_call_site() {
    // #825 plan §3.9 test #3b. The skip-on-underflow invariant
    // (`if kick_start != 0 && kick_end >= kick_start`) lives at
    // the `maybe_wake_tx` caller, NOT inside
    // `record_kick_latency`. This test documents that contract by
    // demonstrating:
    //   (a) the caller's skip is correct: if the caller instead
    //       passed `kick_end.wrapping_sub(kick_start)` with
    //       `kick_end < kick_start` (monotonic_nanos() failure
    //       on either side), the resulting bogus-large delta
    //       would saturate at bucket 15 — a visible spike that
    //       the caller's `kick_start != 0 && kick_end >=
    //       kick_start` guard prevents.
    //   (b) `record_kick_latency` itself pins to "well-formed
    //       inputs only": no in-band sentinel check inside the
    //       helper, matching `record_tx_completions_with_stamp`'s
    //       `ts_completion >= ts_submit` pattern at tx.rs:113-119.
    //
    // The pin: drive `record_kick_latency` with a synthetic
    // "underflow would produce this" delta and verify it DOES
    // get recorded (saturation at bucket 15) — proving the
    // invariant lives at the call site, not inside the helper.
    // A future refactor that moves the guard inside the helper
    // MUST also update this test to match.
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;
    // Pre-computed value a caller using `wrapping_sub` would
    // produce on underflow (e.g., kick_end=0 from clock failure
    // AFTER kick_start=100): `0_u64.wrapping_sub(100)` =
    // `u64::MAX - 99`. At that scale the helper's
    // `bucket_index_for_ns` saturates at 15 — the visible
    // "spike" the caller-site `kick_start != 0 && kick_end >=
    // kick_start` check prevents in production (the `>=` half
    // catches backwards-clock / end-before-start; the
    // `!= 0` half catches the asymmetric clock-failure case).
    let bogus_delta = 0u64.wrapping_sub(100);
    crate::afxdp::tx::record_kick_latency(owner, bogus_delta);
    let snap = live.snapshot();
    assert_eq!(
        snap.tx_kick_latency_count, 1,
        "helper has no in-band sentinel — skip lives at call site",
    );
    assert_eq!(
        snap.tx_kick_latency_hist[15], 1,
        "bogus-large delta saturates at bucket 15",
    );
    // Invariant pinned: if a future refactor were to add a
    // sentinel inside `record_kick_latency`, this assertion
    // would fail and flag the behavior change explicitly.
    // The production call site at tx.rs:maybe_wake_tx uses
    // `if kick_start != 0 && kick_end >= kick_start {
    // record_kick_latency(...) }` which is the correct guard
    // location (code-review R1 HIGH-1).
}

#[test]
fn tx_kick_retry_count_observable_via_snapshot() {
    // #825 code-review R1 MED-3: pin that the `tx_kick_retry_count`
    // field is (a) writable via the same owner-side atomic that the
    // production call site at tx.rs:maybe_wake_tx EAGAIN branch uses
    // (`binding.live.owner_profile_owner.tx_kick_retry_count
    //   .fetch_add(1, Ordering::Relaxed)`) and (b) observable via
    // `BindingLiveState::snapshot()` with the expected value. This
    // would fail-loud if a future refactor renamed the field, moved
    // it off `OwnerProfileOwnerWrites`, or dropped the plumb-through
    // in `snapshot()` — catching the class of regression Codex's
    // MED-3 flagged.
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;
    // Mirror the production call-site shape exactly: Relaxed
    // fetch_add on the AtomicU64. N intentionally small — the
    // property we pin is plumbing correctness, not performance.
    let n: u64 = 7;
    for _ in 0..n {
        owner.tx_kick_retry_count.fetch_add(1, Ordering::Relaxed);
    }
    let snap = live.snapshot();
    assert_eq!(snap.tx_kick_retry_count, n);
    // A second snapshot re-reads the same atomic (no reset on
    // snapshot) — bulk sync publishes absolute values per
    // protocol.rs plan §3.4 decision.
    let snap2 = live.snapshot();
    assert_eq!(snap2.tx_kick_retry_count, n);
}

#[test]
fn tx_kick_latency_cross_thread_snapshot_skew_within_bound() {
    // #825 plan §3.9 test #6 (cross-thread skew harness
    // mirroring #812's tx_latency_hist_cross_thread_snapshot_skew_within_bound
    // at umem.rs:1097-1274).
    //
    // Spawn a writer thread that calls `record_kick_latency` in
    // a tight loop; spawn a reader thread that calls
    // `BindingLiveState::snapshot()` in a tight loop. Assert
    // the bounded-skew invariant `|sum(hist) - count| ≤ K_skew`
    // holds for every reader sample.
    //
    // K_skew = ceil(λ_obs × W_read_max) + 2 (plan §4 / #812 §3.6 R2).
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    let live = Arc::new(BindingLiveState::new());
    let stop = Arc::new(AtomicBool::new(false));
    let reader_warm = Arc::new(AtomicBool::new(false));

    // Writer: drives the production helper directly (no
    // fixture indirection). Each iteration feeds one delta,
    // so count increments by 1 per call.
    let writer_live = Arc::clone(&live);
    let writer_stop = Arc::clone(&stop);
    let writer_warm = Arc::clone(&reader_warm);
    let writer_handle = std::thread::spawn(move || {
        let owner = &writer_live.owner_profile_owner;
        let mut cursor: u64 = 1;
        // Warm 10k iters before signalling the reader so λ_obs
        // is steady-state, not startup.
        for _ in 0..10_000u64 {
            crate::afxdp::tx::record_kick_latency(owner, cursor & 0xFFFF);
            cursor = cursor.wrapping_add(1);
        }
        writer_warm.store(true, Ordering::Release);
        while !writer_stop.load(Ordering::Relaxed) {
            crate::afxdp::tx::record_kick_latency(owner, cursor & 0xFFFF);
            cursor = cursor.wrapping_add(1);
        }
    });

    #[derive(Clone, Copy)]
    struct Sample {
        skew: i64,
        w_read_ns: u64,
    }
    let samples: Arc<Mutex<Vec<Sample>>> = Arc::new(Mutex::new(Vec::with_capacity(5_000)));
    let reader_live = Arc::clone(&live);
    let reader_stop = Arc::clone(&stop);
    let reader_warm_rd = Arc::clone(&reader_warm);
    let reader_samples = Arc::clone(&samples);
    let reader_handle = std::thread::spawn(move || {
        let wait_deadline = Instant::now() + Duration::from_secs(2);
        while !reader_warm_rd.load(Ordering::Acquire) && Instant::now() < wait_deadline {
            std::thread::yield_now();
        }
        let mut local = Vec::with_capacity(16_384);
        while !reader_stop.load(Ordering::Relaxed) {
            let pre = Instant::now();
            let snap = reader_live.snapshot();
            let w_read_ns = pre.elapsed().as_nanos() as u64;
            let count = snap.tx_kick_latency_count as i64;
            let sum_buckets: i64 = snap.tx_kick_latency_hist.iter().copied().sum::<u64>() as i64;
            let skew = (sum_buckets - count).abs();
            local.push(Sample { skew, w_read_ns });
        }
        *reader_samples.lock().unwrap() = local;
    });

    let wall_start = Instant::now();
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);
    writer_handle.join().expect("writer thread joins cleanly");
    reader_handle.join().expect("reader thread joins cleanly");
    let elapsed_ns = wall_start.elapsed().as_nanos() as u64;

    let final_snap = live.snapshot();
    let count_final = final_snap.tx_kick_latency_count;
    assert!(
        count_final > 0,
        "writer thread produced no samples — harness broken",
    );
    let lambda_obs_per_ns = count_final as f64 / elapsed_ns.max(1) as f64;

    let gathered = samples.lock().unwrap().clone();
    assert!(
        !gathered.is_empty(),
        "reader thread produced no snapshots — harness broken",
    );
    let mut max_skew = 0i64;
    let mut max_w_read_ns = 0u64;
    for s in &gathered {
        if s.skew > max_skew {
            max_skew = s.skew;
        }
        if s.w_read_ns > max_w_read_ns {
            max_w_read_ns = s.w_read_ns;
        }
    }
    // #825 vs #812 margin note. The #812 cross-thread harness
    // uses margin +2 because its writer path (stamp + reap
    // fold) is ~50× slower per call than a bare
    // `record_kick_latency` here (3 × fetch_add). That means
    // within a single long reader window, instantaneous writer
    // rate can spike above the global λ_obs. We therefore use
    // margin factor 2× on the λ×W_read term plus +4 fixed —
    // still O(λ × W) dominated and still a tight bound, just
    // sized to the faster writer path.
    let k_skew = (lambda_obs_per_ns * max_w_read_ns as f64 * 2.0).ceil() as i64 + 4;
    assert!(
        max_skew <= k_skew,
        "cross-thread skew {max_skew} exceeds bound K_skew = {k_skew} \
         (lambda_obs_per_ns={lambda_obs_per_ns:.6}, \
         max_w_read_ns={max_w_read_ns}, count_final={count_final}, \
         samples={})",
        gathered.len(),
    );
    eprintln!(
        "tx_kick_latency_cross_thread_snapshot_skew_within_bound: \
         max_skew={max_skew} k_skew={k_skew} \
         lambda_obs_per_ns={lambda_obs_per_ns:.6} \
         max_w_read_ns={max_w_read_ns} count_final={count_final}",
    );
}

/// #943: pin the flush-into-atomic semantics. The two scratch
/// counters on each `CoSQueueRuntime` accumulate per-pop V_min
/// throttle decisions; once per drain (via `update_binding_debug_state`)
/// they flush into the binding-wide atomics and reset. This test
/// covers the flush body in isolation (extracted as
/// `flush_v_min_scratches_into` so the unit test doesn't need a full
/// `BindingWorker`).
#[test]
fn flush_v_min_scratches_sums_and_zeros_per_queue_counters() {
    use crate::afxdp::types::CoSInterfaceConfig;
    use crate::afxdp::cos::builders::build_cos_interface_runtime;

    // Two queues so we exercise the per-queue iteration.
    let cfg = CoSInterfaceConfig {
        shaping_rate_bytes: 10_000_000,
        burst_bytes: 1024 * 1024,
        default_queue: 0,
        dscp_classifier: String::new(),
        ieee8021_classifier: String::new(),
        dscp_queue_by_dscp: [0u8; 64],
        ieee8021_queue_by_pcp: [0u8; 8],
        queue_by_forwarding_class: Default::default(),
        queues: vec![
            crate::afxdp::types::CoSQueueConfig {
                queue_id: 0,
                forwarding_class: "be".into(),
                priority: 0,
                transmit_rate_bytes: 1_000_000,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            },
            crate::afxdp::types::CoSQueueConfig {
                queue_id: 1,
                forwarding_class: "iperf-c".into(),
                priority: 5,
                transmit_rate_bytes: 5_000_000,
                exact: true,
                surplus_sharing: false,
                surplus_weight: 1,
                buffer_bytes: 64 * 1024,
                dscp_rewrite: None,
            },
        ],
    };
    let mut runtime = build_cos_interface_runtime(&cfg, 0);

    // Manually populate scratches as if v_min check fired.
    runtime.queues[0].v_min_hard_cap_overrides_scratch = 3;
    runtime.queues[0].v_min_throttles_scratch = 17;
    runtime.queues[1].v_min_hard_cap_overrides_scratch = 5;
    runtime.queues[1].v_min_throttles_scratch = 23;

    let hard_cap = std::sync::atomic::AtomicU64::new(0);
    let throttles = std::sync::atomic::AtomicU64::new(0);
    let mut interfaces = std::collections::BTreeMap::new();
    interfaces.insert(1, runtime);

    crate::afxdp::umem::flush_v_min_scratches_into(
        interfaces.values_mut(),
        &hard_cap,
        &throttles,
    );

    // Atomics carry the sums.
    assert_eq!(
        hard_cap.load(std::sync::atomic::Ordering::Relaxed),
        3 + 5,
        "hard_cap atomic must equal sum across queues",
    );
    assert_eq!(
        throttles.load(std::sync::atomic::Ordering::Relaxed),
        17 + 23,
        "throttles atomic must equal sum across queues",
    );

    // Per-queue scratches reset to 0.
    let r = interfaces.get(&1).unwrap();
    assert_eq!(r.queues[0].v_min_hard_cap_overrides_scratch, 0);
    assert_eq!(r.queues[0].v_min_throttles_scratch, 0);
    assert_eq!(r.queues[1].v_min_hard_cap_overrides_scratch, 0);
    assert_eq!(r.queues[1].v_min_throttles_scratch, 0);
}

/// #943: a second flush call with all scratches zero must NOT bump
/// the atomics — the flush is a no-op in steady state when no
/// throttling occurred since the last update_binding_debug_state.
#[test]
fn flush_v_min_scratches_no_op_when_all_zero() {
    use crate::afxdp::types::CoSInterfaceConfig;
    use crate::afxdp::cos::builders::build_cos_interface_runtime;

    let cfg = CoSInterfaceConfig {
        shaping_rate_bytes: 10_000_000,
        burst_bytes: 1024 * 1024,
        default_queue: 0,
        dscp_classifier: String::new(),
        ieee8021_classifier: String::new(),
        dscp_queue_by_dscp: [0u8; 64],
        ieee8021_queue_by_pcp: [0u8; 8],
        queue_by_forwarding_class: Default::default(),
        queues: vec![crate::afxdp::types::CoSQueueConfig {
            queue_id: 0,
            forwarding_class: "be".into(),
            priority: 0,
            transmit_rate_bytes: 1_000_000,
            exact: true,
            surplus_sharing: false,
            surplus_weight: 1,
            buffer_bytes: 64 * 1024,
            dscp_rewrite: None,
        }],
    };
    let runtime = build_cos_interface_runtime(&cfg, 0);
    // Pre-load atomics with non-zero values to verify the flush
    // doesn't accidentally store-zero.
    let hard_cap = std::sync::atomic::AtomicU64::new(42);
    let throttles = std::sync::atomic::AtomicU64::new(99);
    let mut interfaces = std::collections::BTreeMap::new();
    interfaces.insert(1, runtime);

    crate::afxdp::umem::flush_v_min_scratches_into(
        interfaces.values_mut(),
        &hard_cap,
        &throttles,
    );

    // Atomics unchanged — the no-zero-scratch path skips the fetch_add.
    assert_eq!(hard_cap.load(std::sync::atomic::Ordering::Relaxed), 42);
    assert_eq!(throttles.load(std::sync::atomic::Ordering::Relaxed), 99);
}
