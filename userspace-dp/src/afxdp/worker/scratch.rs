//! #959 Phase 2 — extracts the per-binding `scratch_*` reusable
//! buffers out of `BindingWorker` into a dedicated `WorkerScratch`
//! sub-struct.
//!
//! These vectors are pre-allocated once and reused every poll cycle
//! to avoid per-packet allocations. They're cleared at the start of
//! each cycle and pushed-to as the descriptor loop produces work for
//! the TX submit / fill / recycle / cross-binding handoff stages.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-2. Field names preserved so the
//! `binding.scratch.scratch_X` access pattern keeps the same
//! grep-friendly suffix as the original `binding.scratch_X`.
//! (Rust's default `repr(Rust)` does not guarantee layout, so this
//! says nothing about field ordering or struct size.)

use super::*;

/// Per-binding reusable scratch buffers cleared each poll cycle.
///
/// Naming preserves the historical `scratch_*` prefix inside the
/// struct so callers find the same field name with `.scratch.` in
/// front: `binding.scratch.scratch_recycle` (was
/// `binding.scratch_recycle`).
///
/// **Intentionally NOT `Default`.** Codex round-1 review on
/// PR #1168 flagged that a `#[derive(Default)]` would silently
/// produce zero-capacity Vecs on accidental
/// `WorkerScratch::default()` calls, regressing the no-allocation-
/// on-hot-path contract. The only legal construction path is
/// [`WorkerScratch::pre_sized`], which carries the per-Vec
/// `with_capacity` hints.
///
/// #7212: that constructor replaces the three IDENTICAL struct literals
/// `BindingWorker::create` and its two siblings in `worker/mod.rs` used to
/// carry. Three copies of a thirteen-field pre-sizing table is a place where a
/// new buffer has to be added three times and can be pre-sized differently in
/// each — and adding the thirteenth was what pushed `worker/mod.rs` past the
/// 2000-LOC [REFACTOR] floor. One constructor removes both problems: the
/// capacity policy lives once, next to the fields it sizes.
pub(crate) struct WorkerScratch {
    pub(crate) scratch_recycle: Vec<u64>,
    pub(crate) scratch_forwards: Vec<PendingForwardRequest>,
    pub(crate) scratch_fill: Vec<u64>,
    pub(crate) scratch_prepared_tx: Vec<PreparedTxRequest>,
    pub(crate) scratch_local_tx: Vec<(u64, TxRequest)>,
    /// #5157: identity of the local-TX items that `transmit_batch`
    /// actually committed, as ORIGINAL-`pending` positions (0-based, in
    /// the order the caller built its per-item sidecars). Filled fresh
    /// on every `transmit_batch` call (cleared at entry). Needed because
    /// the mirror-reserve back-pressure drops a `mirror_clone` request
    /// mid-batch via `continue` — a NON-prefix / interior removal — so
    /// the committed set is no longer a prefix of the input. Only
    /// `submit_local` reads it (to charge flow-bucket / sojourn
    /// accounting to the correct flow); other `transmit_batch` callers
    /// ignore it.
    pub(crate) scratch_committed_orig_idx: Vec<u16>,
    pub(crate) scratch_exact_prepared_tx: Vec<ExactPreparedScratchTxRequest>,
    pub(crate) scratch_exact_local_tx: Vec<ExactLocalScratchTxRequest>,
    pub(crate) scratch_completed_offsets: Vec<u64>,
    pub(crate) scratch_post_recycles: Vec<(u32, u64)>,
    /// Flow cache fast-path: cross-binding in-place rewrites
    /// deferred until after the RX batch (the borrow checker
    /// prevents mutable access to two bindings simultaneously
    /// inside the RX loop). Reserved for the cross-binding
    /// fast-path; not yet wired (hence `#[allow(dead_code)]`).
    #[allow(dead_code)]
    pub(crate) scratch_cross_binding_tx: Vec<(usize, PreparedTxRequest)>,
    pub(crate) scratch_rst_teardowns: Vec<(SessionKey, NatDecision)>,
    /// #7212: forward + reverse keys of every session this poll pass REVOKED
    /// because a static interface INPUT filter now denies it.
    ///
    /// Deferred rather than evicted inline for the same borrow-checker reason as
    /// `scratch_cross_binding_tx`: the eviction has to run on EVERY binding of
    /// this worker (a session does not carry the ingress ifindex the flow cache
    /// is keyed on, and the two directions of one flow can be cached on
    /// different bindings), and the RX loop holds `&mut BindingWorker` for one
    /// binding only. `worker/lifecycle.rs` drains it under the
    /// `left`/`current`/`right` split borrow, in the SAME tick, before any
    /// further packet is processed.
    ///
    /// Sized for the worst case an RX batch can produce so a push inside the
    /// packet loop cannot reallocate: up to `RX_BATCH_SIZE` descriptors, each
    /// able to revoke one session, and each revocation pushing the canonical
    /// key, its companion, and the wire tuple the packet carried (which differs
    /// from the canonical key on the NAT reverse-translated alias path and keys
    /// its own flow-cache slot). Drained and returned to the binding each pass,
    /// keeping that capacity.
    pub(crate) scratch_filter_revoked_keys: Vec<SessionKey>,
    pub(crate) pmech_injected_replay_addrs: Vec<u64>,
}

impl WorkerScratch {
    /// The ONE construction path: every buffer pre-allocated at the capacity
    /// its stage actually needs, so the poll cycle never reallocates.
    ///
    /// `ring_entries` sizes `scratch_completed_offsets` alone — it is drained
    /// against the completion ring, so its bound is the ring's, not a batch's.
    /// Every other capacity is a compile-time batch bound.
    /// #7212: the revoked-key buffer's bound — see
    /// `scratch_filter_revoked_keys`. Three keys per revoked session, one
    /// revocation per descriptor at worst.
    pub(crate) const REVOKED_KEYS_PER_DESCRIPTOR: usize = 3;

    pub(crate) fn pre_sized(ring_entries: u32) -> Self {
        Self {
            scratch_recycle: Vec::with_capacity(
                RX_BATCH_SIZE as usize + crate::session::PMECH_MAX_HELD_WAITERS_TOTAL,
            ),
            scratch_forwards: Vec::with_capacity(RX_BATCH_SIZE as usize),
            scratch_fill: Vec::with_capacity(FILL_BATCH_SIZE),
            scratch_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
            scratch_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
            scratch_committed_orig_idx: Vec::with_capacity(TX_BATCH_SIZE),
            scratch_exact_prepared_tx: Vec::with_capacity(TX_BATCH_SIZE),
            scratch_exact_local_tx: Vec::with_capacity(TX_BATCH_SIZE),
            scratch_completed_offsets: Vec::with_capacity(ring_entries as usize),
            scratch_post_recycles: Vec::with_capacity(RX_BATCH_SIZE as usize),
            scratch_cross_binding_tx: Vec::with_capacity(RX_BATCH_SIZE as usize),
            scratch_rst_teardowns: Vec::with_capacity(16),
            // #7212: pre-sized for the worst case ONE RX batch can produce, so
            // a push inside the packet loop never reallocates. The old
            // hand-written 16 was under the bound by 12x.
            scratch_filter_revoked_keys: Vec::with_capacity(
                RX_BATCH_SIZE as usize * Self::REVOKED_KEYS_PER_DESCRIPTOR,
            ),
            pmech_injected_replay_addrs: Vec::new(),
        }
    }
}
