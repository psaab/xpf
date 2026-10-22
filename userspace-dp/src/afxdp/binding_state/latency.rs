// Latency-histogram primitives for the binding-state telemetry:
// the shared power-of-two bucket select (`bucket_index_for_ns`), the
// bucket-count wire-contract constants (`DRAIN_HIST_BUCKETS`,
// `TX_SUBMIT_LAT_BUCKETS`), the redirect-acquire 1-in-256 sampler
// (`REDIRECT_SAMPLE_MASK` + the producer-local `REDIRECT_SAMPLE_SEQ`
// thread-local), and the TX-submit sidecar sentinel
// (`TX_SIDECAR_UNSTAMPED`). Extracted from `umem/mod.rs` (#6436).
//
// The bucket layout is part of the wire contract (protocol.rs +
// Prometheus labels): any future change must propagate through both
// sides, so the const-asserts below force a compile error on a
// silent edit.

/// #709: owner-drain / redirect-acquire latency histogram bucket count.
///
/// Bucket layout (produced by `bucket_index_for_ns`):
/// - Bucket 0: `[0, 1024 ns)` — the sub-1 µs catch-all.
/// - Bucket 1: `[1024, 2048)` = `[2^10, 2^11)` ns.
/// - Bucket N (N >= 1): `[2^(N+9), 2^(N+10))` ns.
/// - Bucket 15: saturation — any ns ≥ 2^24 (~16 ms) lands here.
///
/// Indexed branchlessly (one `leading_zeros` + one saturating subtract
/// + one min). Sized `[AtomicU64; DRAIN_HIST_BUCKETS]` on
/// `BindingLiveState` so the entire histogram lives inline in the
/// owner's `Arc<BindingLiveState>` — no heap allocation, no bucket-
/// search loop on the hot path. The const-assert below exists because
/// the bucket layout is part of the wire contract (protocol.rs +
/// Prometheus labels): any future change must propagate through both
/// sides, so force a compile error on a silent edit.
pub(in crate::afxdp) const DRAIN_HIST_BUCKETS: usize = 16;
const _: () = assert!(DRAIN_HIST_BUCKETS == 16);

/// #709: sample mask for the redirect-acquire timer. We sample the
/// timer 1-in-(MASK+1) = 1-in-256 pushes. The mask is required to be a
/// power-of-two minus one so `counter & MASK == 0` fires uniformly on
/// exactly one value per wrap.
pub(in crate::afxdp) const REDIRECT_SAMPLE_MASK: u64 = 0xff;
const _: () = assert!(REDIRECT_SAMPLE_MASK.count_ones() == REDIRECT_SAMPLE_MASK.trailing_ones());

thread_local! {
    /// #5160: PRODUCER-LOCAL redirect-sample sequence. Before #5160 this was a
    /// shared `AtomicU64` (`redirect_sample_counter`) on the DESTINATION
    /// `BindingLiveState.owner_profile_peer`, so every producer worker
    /// redirecting into one owner binding paid a contended `fetch_add` RMW on
    /// that shared cacheline for EVERY MPSC enqueue — a 1-in-256 sampler
    /// imposing a 1-in-1 shared atomic, turning one contended sequencing line
    /// (the inbox head CAS) into two. A `Cell<u64>` in thread-local storage
    /// gives each producer worker (its own OS thread) its OWN sequence — a plain
    /// TLS load/store, no atomic, no shared cacheline. The aggregate sample RATE
    /// is unchanged: each producer samples 1-in-(`REDIRECT_SAMPLE_MASK`+1) of
    /// its own enqueues, so each destination's `redirect_acquire_hist` still
    /// receives ~1/256 of the enqueues INTO it (only the sampled op touches the
    /// shared destination histogram, exactly as before).
    static REDIRECT_SAMPLE_SEQ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// #5160: advance this producer thread's redirect-sample sequence and report
/// whether THIS push is the sampled 1-in-(`REDIRECT_SAMPLE_MASK`+1) op. Purely
/// thread-local — no shared atomic on the redirect hot path.
#[inline]
pub(super) fn next_redirect_sample() -> bool {
    REDIRECT_SAMPLE_SEQ.with(|seq| {
        let v = seq.get();
        seq.set(v.wrapping_add(1));
        (v & REDIRECT_SAMPLE_MASK) == 0
    })
}

/// #812: per-queue TX submit→completion latency histogram bucket count.
///
/// Same layout and math as `DRAIN_HIST_BUCKETS` (reuses
/// `bucket_index_for_ns`). Named distinctly so a future re-layout of
/// either histogram cannot silently drift the other — a rename of one
/// does not touch the other's wire contract. The paired const-asserts
/// below tie the two to each other AND pin the bucket count at 16 so
/// a silent drift on either side becomes a build error pointing at
/// this specific wire-contract dependency (Codex LOW #13 / plan §3.2).
pub(in crate::afxdp) const TX_SUBMIT_LAT_BUCKETS: usize = DRAIN_HIST_BUCKETS;
const _ASSERT_TX_SUBMIT_BUCKET_COUNT_MATCHES_DRAIN: () =
    assert!(TX_SUBMIT_LAT_BUCKETS == DRAIN_HIST_BUCKETS);
const _ASSERT_TX_SUBMIT_BUCKET_COUNT_IS_16: () = assert!(TX_SUBMIT_LAT_BUCKETS == 16);

/// #16242: descriptors-per-commit histogram bucket count. Bucket `i`
/// covers commit size `i + 1` for `i < 7`; bucket 7 covers `[8, 16)`;
/// bucket 8 `[16, 32)`; bucket 9 `[32, 64)`; bucket 10 saturates at
/// `>= TX_BATCH_SIZE` (64). Zero-insert commits are not samples (see
/// `record_tx_commit` in tx/stats.rs) — they carry no batch-depth
/// information and are already counted by `dbg_tx_ring_full`.
pub(in crate::afxdp) const TX_BATCH_BUCKETS: usize = 11;
const _: () = assert!(TX_BATCH_BUCKETS == 11);

/// #16242: branchless bucket select for a TX commit size in
/// `[1, TX_BATCH_SIZE]`. Sizes 1..=7 map to buckets 0..=6; larger sizes
/// use `31 - leading_zeros(n)` so 8..=15 → 7, 16..=31 → 8,
/// 32..=63 → 9, 64 → 10 (clamped). One `leading_zeros`, no loop.
#[inline]
pub(in crate::afxdp) fn tx_batch_bucket(inserted: u32) -> usize {
    debug_assert!(inserted >= 1);
    if inserted < 8 {
        (inserted - 1) as usize
    } else {
        ((31 - inserted.leading_zeros() + 4) as usize).min(TX_BATCH_BUCKETS - 1)
    }
}

/// #812: sentinel for unstamped sidecar slots. A completion seen
/// against this value means the submit stamp was never written (e.g.
/// a surviving offset across a restart, or a `monotonic_nanos() == 0`
/// clock-gettime failure where `stamp_submits` early-returned without
/// touching the slot — `tx/stats.rs::stamp_submits`). The reap path MUST
/// skip the histogram increment for these so the tail of the
/// distribution is not silently biased toward bucket 0 (plan §5.4).
///
/// We pick `u64::MAX` because a legitimate monotonic timestamp cannot
/// reach it — at nanosecond granularity it is ~585 years of uptime,
/// well past any deployment lifetime. This removes any value
/// collision between "just happened, small stamp" and "unstamped".
///
/// Codex round-1 MED + Rust round-1 MED-2: the previous
/// `canonical_submit_stamp(ts == 0) → sentinel` mapping in `tx.rs`
/// was in-band signalling on a u64 and has been removed. Clock-
/// failure is now a no-op at stamp time; the slot's pre-existing
/// `UNSTAMPED` state (set by `record_tx_completions_with_stamp` on
/// the previous reap, or by worker construction) is what causes the
/// reap to skip the sample.
pub(in crate::afxdp) const TX_SIDECAR_UNSTAMPED: u64 = u64::MAX;

/// #709: branchless power-of-two bucket select for nanosecond deltas.
///
/// Mapping (see `DRAIN_HIST_BUCKETS` for the layout):
/// - `ns ∈ [0, 1024)` → bucket 0 (sub-1 µs catch-all).
/// - `ns ∈ [2^(N+9), 2^(N+10))` → bucket N, for N ∈ [1, 15).
/// - `ns ≥ 2^24` → bucket 15 (saturation).
///
/// Formula:
/// - `(ns | 1)` ensures `leading_zeros` sees at least one set bit —
///   `leading_zeros(0) == 64` would otherwise land us one bucket off
///   at the bottom. With the OR, `ns=0` behaves like `ns=1` (bucket 0).
/// - `clz = (ns | 1).leading_zeros()`: for `ns=1024 (2^10)`,
///   `clz = 64 - 11 = 53`; for `ns=2^24` (top bucket lower bound),
///   `clz = 64 - 25 = 39`.
/// - `b = 54 - clz` gives bucket 1 for `ns=1024` and bucket 15 for
///   `ns=2^24`. Sub-1024 ns delta yields `clz >= 54` → `b <= 0`, which
///   the `.max(0)` saturating subtract clamps at 0. Above 2^24, `b`
///   grows past 15, which `.min(DRAIN_HIST_BUCKETS - 1)` clamps.
///
/// One `leading_zeros` + one saturating subtract + one min. No loop,
/// no branch. Hot-path OK per plan §5.
#[inline]
pub(in crate::afxdp) fn bucket_index_for_ns(ns: u64) -> usize {
    let clz = (ns | 1).leading_zeros() as i32;
    let b = (54 - clz).max(0) as usize;
    b.min(DRAIN_HIST_BUCKETS - 1)
}
