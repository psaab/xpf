// Single-writer (owner worker thread): per-frame counters use
// `Ordering::Relaxed` and the sidecar `&mut [u64]` is non-atomic.

use std::sync::atomic::Ordering;

use crate::afxdp::binding_state::{
    bucket_index_for_ns, OwnerProfileOwnerWrites,
    TX_SIDECAR_UNSTAMPED, TX_SUBMIT_LAT_BUCKETS,
};
use crate::afxdp::UMEM_FRAME_SHIFT;

/// #812 Codex round-1 MED + Rust round-1 MED-2: replaced the former
/// `canonical_submit_stamp` in-band mapping of `ts == 0 → sentinel`
/// with an early-return in `stamp_submits`. The sentinel is
/// `u64::MAX` (see `binding_state/latency.rs::TX_SIDECAR_UNSTAMPED`); a legitimate
/// monotonic timestamp cannot reach it (~585 years at ns granularity).
/// Previously, the Rust reviewer flagged the `ts == 0` branch as
/// in-band signalling on a u64. We now skip all sidecar writes on
/// clock failure rather than overwriting fresh data with the sentinel
/// — safe because `record_tx_completions_with_stamp` resets each
/// slot to `TX_SIDECAR_UNSTAMPED` on reap, so a frame whose sidecar
/// did NOT receive a stamp in the current cycle is already in the
/// correct "skip at reap time" state.

/// #812: stamp the submit-timestamp sidecar for the accepted prefix
/// of the current TX batch. Called ONCE per `writer.commit()` at each
/// of the six submit sites (plan §3.1 table) with the scratch
/// offsets. Only the first `inserted` offsets are stamped; the retry
/// tail (`scratch[inserted..]`) MUST NOT be stamped because those
/// descriptors return to `free_tx_frames` and would otherwise produce
/// phantom completions bucketed against a stale submit time.
///
/// Codex round-1 HIGH #1: call sites MUST invoke this AFTER
/// `writer.commit()` (and `drop(writer)`). Pre-commit stamping
/// attributed a scheduler preemption window between `insert` and ring
/// submission to the kernel-visible submit→completion latency, which
/// is exactly backwards. Post-commit stamping reflects the moment the
/// ring producer actually became kernel-visible.
///
/// Single-writer: the owner worker is the only thread that touches
/// this sidecar (see plan §3.3 file citations: `WorkerUmem` is `Rc`
/// at `umem/mod.rs`, `free_tx_frames` is plain `VecDeque` at
/// `worker.rs:16`). Plain slice-indexed store — no atomic, no grow.
#[inline]
pub(in crate::afxdp) fn stamp_submits<I>(sidecar: &mut [u64], offsets: I, ts_submit: u64)
where
    I: Iterator<Item = u64>,
{
    // #812 Codex round-1 MED + Rust round-1 MED-2: clock-failure gate.
    // `monotonic_nanos()` returns 0 on `clock_gettime` failure
    // (`neighbor.rs:8-10`). On failure we do NOT overwrite sidecar
    // slots with a sentinel — we return without touching any slot.
    // `record_tx_completions_with_stamp` resets each slot to
    // `TX_SIDECAR_UNSTAMPED` on reap, so a slot that skipped its
    // stamp this cycle already reads as "unstamped" at reap time and
    // the sample is correctly dropped. This removes the previous
    // in-band mapping of `ts == 0 → TX_SIDECAR_UNSTAMPED`.
    //
    // The sentinel itself stays at `u64::MAX` — a legitimate
    // monotonic timestamp cannot reach it (~585 years uptime at ns
    // granularity), so there is no value collision between a
    // genuine-but-small stamp and "unstamped".
    if ts_submit == 0 {
        return;
    }
    for offset in offsets {
        let idx = (offset >> UMEM_FRAME_SHIFT) as usize;
        // #15244 (A61-01): the sidecar is sized to the WHOLE UMEM
        // region (`worker_umem.total_frames()` — the group sum under
        // a shared UMEM; see `tx_submit_sidecar_len`), so every
        // offset this binding can legally submit — including a
        // shared secondary's `[N, 2N)` carve-out — indexes inside
        // its OWN sidecar and is stamped here, by its own owner.
        // The former claim that an out-of-range offset "belongs to
        // a different binding's sidecar" was the bug: offsets are
        // region-wide, the secondary's stamps landed above its
        // per-binding-sized sidecar, and this `get_mut` silently
        // dropped every one of them (the reap fold dropped the
        // matching completions the same way), so the #812 histogram
        // covered only a direction-dependent subset. `get_mut`
        // remains as a soundness guard for a genuinely foreign
        // offset (past the whole region — a stale/cross-restart
        // completion, never a live submit from this binding): it
        // returns None and the stamp is dropped rather than
        // corrupting an unrelated slot.
        // Pinned by the `tx_latency_hist_shared_umem_*` tests in
        // `binding_state/tests` (canonical pin location after
        // #984 P2a — these tests reach this fn via
        // `crate::afxdp::tx::stamp_submits` through the load-bearing
        // re-export in `tx/mod.rs`).
        //
        // `debug_assert!` is deliberately NOT used here: tests drive
        // this path directly and we want release-parity semantics
        // (silent drop) to be the PRIMARY pin, not a test-only panic.
        if let Some(slot) = sidecar.get_mut(idx) {
            *slot = ts_submit;
        }
    }
}

/// #825: record a single `sendto` kick-latency sample into the owner
/// atomics. Mirrors the shape of `record_tx_completions_with_stamp`
/// but without the sidecar fold (the kick site stamps the bracket
/// directly, no submit/completion indirection). Called once per TX
/// kick on the hot path from `maybe_wake_tx` after the sentinel
/// check; `#[inline]` to elide the call overhead.
///
/// Single-writer: the owner worker is the only thread that calls
/// this for a given binding. Readers (`BindingLiveState::snapshot()`)
/// see the atomics via `Relaxed`; bounded-read-skew semantics per
/// plan §4 (K_skew inherited from #812 as a conservative upper
/// bound — kicks occur strictly less frequently than completions).
#[inline]
pub(in crate::afxdp) fn record_kick_latency(owner: &OwnerProfileOwnerWrites, delta_ns: u64) {
    let bucket = bucket_index_for_ns(delta_ns);
    owner.tx_kick_latency_hist[bucket].fetch_add(1, Ordering::Relaxed);
    owner.tx_kick_latency_count.fetch_add(1, Ordering::Relaxed);
    owner
        .tx_kick_latency_sum_ns
        .fetch_add(delta_ns, Ordering::Relaxed);
}

/// #812 test hook / decomposition aid: the pure per-offset fold from
/// `reap_tx_completions`. Takes the sidecar slice, the list of
/// completed offsets, and an injected `ts_completion` (so tests can
/// drive deterministic deltas), plus the owner-profile atomic set.
/// Same shape the live reap path runs — batched aggregation into
/// local counters followed by at most N_buckets `fetch_add`s — so
/// unit pins here exercise the production algorithm, not a test-only
/// fake.
///
/// Returns `(count, sum_ns)` for callers that want to assert on the
/// per-batch delta directly (rather than reading back the atomics
/// afterward).
#[inline]
pub(in crate::afxdp) fn record_tx_completions_with_stamp(
    sidecar: &mut [u64],
    completed_offsets: &[u64],
    ts_completion: u64,
    owner: &OwnerProfileOwnerWrites,
) -> (u64, u64) {
    let mut hist_fire_count = 0u64;
    let mut hist_fire_sum_ns = 0u64;
    let mut hist_fire_per_bucket = [0u64; TX_SUBMIT_LAT_BUCKETS];
    for &offset in completed_offsets {
        let slot_idx = (offset >> UMEM_FRAME_SHIFT) as usize;
        let ts_submit = match sidecar.get_mut(slot_idx) {
            Some(slot) => {
                let v = *slot;
                *slot = TX_SIDECAR_UNSTAMPED;
                v
            }
            None => TX_SIDECAR_UNSTAMPED,
        };
        if ts_submit != TX_SIDECAR_UNSTAMPED && ts_completion >= ts_submit {
            let delta_ns = ts_completion - ts_submit;
            let bucket = bucket_index_for_ns(delta_ns);
            hist_fire_per_bucket[bucket] = hist_fire_per_bucket[bucket].saturating_add(1);
            hist_fire_count = hist_fire_count.saturating_add(1);
            hist_fire_sum_ns = hist_fire_sum_ns.saturating_add(delta_ns);
        }
    }
    for (b, add) in hist_fire_per_bucket.iter().enumerate() {
        if *add != 0 {
            owner.tx_submit_latency_hist[b].fetch_add(*add, Ordering::Relaxed);
        }
    }
    if hist_fire_count != 0 {
        owner
            .tx_submit_latency_count
            .fetch_add(hist_fire_count, Ordering::Relaxed);
        owner
            .tx_submit_latency_sum_ns
            .fetch_add(hist_fire_sum_ns, Ordering::Relaxed);
    }
    (hist_fire_count, hist_fire_sum_ns)
}
