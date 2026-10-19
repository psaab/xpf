//! #959 Phase 7 — extracts the per-binding TX pipeline state out of
//! `BindingWorker` into a dedicated `WorkerTxPipeline` sub-struct.
//! #959 Phase 10 — adds `outstanding_tx` to this same sub-struct
//! (was held back from Phase 7 to avoid collision with the
//! `BindingStatus.outstanding_tx` snapshot mirror; the type-level
//! disambiguation now keeps the two distinct).
//!
//! These eight fields hold the per-binding TX pipeline buffers and
//! the per-frame submit-timestamp sidecar:
//!
//! - `free_tx_frames` — UMEM frame addresses available for TX.
//! - `pending_tx_prepared` — TX-ready requests awaiting ring submit.
//! - `pending_tx_local` — local-TX requests awaiting ring submit.
//! - `max_pending_tx` — TX backpressure threshold (configured once).
//! - `outstanding_tx` — transient gauge of in-flight TX descriptors
//!   (incremented when a TX ring descriptor is inserted, decremented
//!   when the completion ring is reaped — `sendto` is the wake/kick,
//!   not the increment site). Mirrored to
//!   `BindingLiveState.debug_outstanding_tx` once per debug tick so
//!   the snapshot reader sees a recent value (#802).
//! - `pending_fill_frames` — fill-ring back-pressure queue.
//! - `in_flight_prepared_recycles` — completion-time recycle map.
//! - `tx_submit_ns` — per-UMEM-frame submit timestamp sidecar
//!   (#812). Pre-allocated to the WHOLE UMEM region's frame count
//!   (`worker_umem.total_frames()`) at construction — under a shared
//!   UMEM that is the group sum, not this binding's own carve-out,
//!   because frame offsets are region-wide (#15244 A61-01); never
//!   grown. `Box<[u64]>` (not `Vec<u64>`) at the type level
//!   so any future `push` attempt fails to compile.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-7/10. Field names preserved so
//! `binding.tx_pipeline.free_tx_frames` keeps the same grep-friendly
//! suffix as the original `binding.free_tx_frames`.

use super::*;

/// Per-binding TX pipeline state. See module-level docs.
///
/// **Intentionally NOT `Default`** — `tx_submit_ns` must be sized
/// to the whole UMEM region (`worker_umem.total_frames()`) at
/// construction, not zero-length and not this binding's own frame
/// count. Construction goes through the explicit literal in
/// `BindingWorker::create`, which sizes it via
/// `tx_submit_sidecar_len`.
pub(crate) struct WorkerTxPipeline {
    pub(crate) free_tx_frames: VecDeque<u64>,
    pub(crate) pending_tx_prepared: VecDeque<PreparedTxRequest>,
    pub(crate) pending_tx_local: VecDeque<TxRequest>,
    /// #7204 (A1-b6-F4): worker-owned scratch for the non-CoS backup drain's
    /// retry queue, parked here between batches so its allocation is recycled.
    ///
    /// The backup drain used `VecDeque::new()` per batch and, on FULL SUCCESS,
    /// skipped the restore and dropped BOTH deques — the fresh retry queue AND
    /// the `pending_tx_local` allocation it had `mem::take`n. So the common,
    /// everything-transmitted path re-allocated two deques on the next batch,
    /// on the warmed TX path that is supposed to be allocation-free.
    ///
    /// Always empty between batches: the drain takes it, fills and drains it,
    /// and parks whichever deque is not being handed back to `pending_tx_local`.
    pub(crate) backup_retry_scratch: VecDeque<TxRequest>,
    pub(crate) max_pending_tx: usize,
    /// Transient gauge of in-flight TX descriptors — incremented
    /// when a TX ring descriptor is inserted (the
    /// `saturating_add(inserted)` sites in tx/transmit.rs and the
    /// CoS direct-submit paths in cos/queue_service/service.rs),
    /// decremented when the completion ring is reaped
    /// (saturating_sub in tx/rings.rs). `sendto` is the wake/kick
    /// of the kernel TX path, NOT the increment site. Mirrored once
    /// per debug tick to `BindingLiveState.debug_outstanding_tx`
    /// for the snapshot reader (#802). NOT a counter — a
    /// saturating gauge of in-flight work.
    pub(crate) outstanding_tx: u32,
    pub(crate) pending_fill_frames: VecDeque<u64>,
    pub(crate) in_flight_prepared_recycles: FastMap<u64, PreparedTxRecycle>,
    /// #9900 F-092 (GPT-2): ownership set for UNTRACKED TX submits (local-TX
    /// + `FreeTxFrame` prepared). Inserted at submit-settle for the
    /// kernel-accepted prefix, removed by the completion else-branch; a
    /// completion for an offset NOT in the set is a duplicate, stale, or
    /// never-submitted fault and is dropped + counted instead of
    /// double-pushed into the free pool. (Tracked `Fill*` submits already
    /// carry exact ownership in `in_flight_prepared_recycles`.)
    pub(crate) in_flight_untracked_tx: FastSet<u64>,
    /// #812 per-UMEM-frame submit timestamp sidecar. Indexed by
    /// `offset >> UMEM_FRAME_SHIFT`, where the offset spans the
    /// WHOLE UMEM region. Pre-allocated to
    /// `worker_umem.total_frames()` at `BindingWorker::create` —
    /// under a shared UMEM the group sum, so a secondary whose
    /// frames live at `[N, 2N)` still stamps its own slots (#15244
    /// A61-01) — so the hot-path stamp write is a single store —
    /// NO allocation, NO grow. `Box<[u64]>` (not `Vec<u64>`) at
    /// the type level so any future `push` attempt fails to
    /// compile (Rust round-1 MED-1). Unstamped slots hold
    /// `TX_SIDECAR_UNSTAMPED` (`u64::MAX`); the reap path skips
    /// the histogram increment for these to avoid biasing the
    /// tail toward bucket 0 (plan §5.4).
    pub(crate) tx_submit_ns: Box<[u64]>,
}

/// #15244 (A61-01): length of the per-binding submit-timestamp
/// sidecar. Frame offsets are UMEM-region-wide: `WorkerUmemPool`
/// fills one pool for the whole shared group and each binding pops
/// its carve-out sequentially, so a secondary owns offsets in
/// `[N, 2N)` while its own `binding_frame_count_for_driver` count
/// is only `N`. Sizing the sidecar to that per-binding count made
/// `stamp_submits` silently drop every stamp above it (and the reap
/// fold drop every matching completion), so the #812 histogram
/// covered only the owner / a direction-dependent subset. The
/// sidecar MUST span the whole region — `worker_umem.total_frames()`
/// (the group sum under a shared UMEM, the binding's own count for
/// a private UMEM, where the two coincide). Pure so the sizing
/// decision is unit-testable without a bound socket; the production
/// caller is `BindingWorker::create`.
pub(crate) fn tx_submit_sidecar_len(worker_umem: &WorkerUmem) -> usize {
    worker_umem.total_frames().max(1) as usize
}

impl WorkerTxPipeline {
    /// #7204 (A1-b6-F4): park the two deques a backup drain finishes with, so
    /// neither allocation is dropped.
    ///
    /// `pending` is the drained request queue this drain `mem::take`-d out of
    /// `pending_tx_local`; `retry` is the batch's retry queue. Exactly one of
    /// them may still hold items, and it is the one that must go back to
    /// `pending_tx_local` — `restore` prepends, so handing over the empty one
    /// would put untransmitted requests BEHIND newly-arrived ones. The other is
    /// parked as next batch's scratch.
    ///
    /// Returns the deque the caller must restore into `pending_tx_local`,
    /// having already parked the other. Split out of the drain so the property
    /// is testable: `WorkerTxPipeline` is constructible in a unit test and
    /// `BindingWorker` (which owns an XSK device) is not.
    /// #7204: an empty pipeline for unit tests. `BindingWorker` owns an XSK
    /// device and cannot be constructed in-process, so a test that needs to
    /// observe the deque handoff needs this type on its own.
    #[cfg(test)]
    pub(crate) fn empty_for_test() -> Self {
        Self {
            free_tx_frames: VecDeque::new(),
            pending_tx_prepared: VecDeque::new(),
            pending_tx_local: VecDeque::new(),
            backup_retry_scratch: VecDeque::new(),
            max_pending_tx: 0,
            outstanding_tx: 0,
            pending_fill_frames: VecDeque::new(),
            in_flight_prepared_recycles: FastMap::default(),
            in_flight_untracked_tx: FastSet::default(),
            tx_submit_ns: Box::new([]),
        }
    }

    pub(crate) fn park_drained_deques(
        &mut self,
        pending: VecDeque<TxRequest>,
        retry: VecDeque<TxRequest>,
    ) -> VecDeque<TxRequest> {
        if retry.is_empty() {
            self.backup_retry_scratch = retry;
            pending
        } else {
            self.backup_retry_scratch = pending;
            retry
        }
    }
}
