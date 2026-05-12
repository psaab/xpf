//! #959 Phase 3 — extracts the per-binding `cos_*` CoS-engine state
//! out of `BindingWorker` into a dedicated `WorkerCos` sub-struct.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-3. Field names preserved so the
//! `binding.cos.cos_X` access pattern keeps the same grep-friendly
//! suffix as the original `binding.cos_X`.
//!
//! Filename is `cos_state.rs`, not `cos.rs`, because the
//! `worker::cos` module already exists (it holds the worker-side
//! CoS runtime helpers). This module exclusively defines the data-
//! holding sub-struct.

use super::*;

/// Per-binding CoS scheduling state. Owned by the worker that owns
/// this binding.
///
/// **Intentionally NOT `Default`** — for consistency with the
/// `WorkerScratch` decomposition pattern (#1168), where Default
/// would have silently regressed Vec capacity. A `WorkerCos::default()`
/// would technically produce the same state as the explicit literal
/// in `BindingWorker::create` (FastMaps are equally `default()`'d
/// there) — but blocking it forces all construction through the
/// explicit literal so any future field with non-trivial init
/// requirements can't accidentally bypass it.
pub(crate) struct WorkerCos {
    pub(crate) cos_fast_interfaces: FastMap<i32, WorkerCoSInterfaceFastPath>,
    pub(crate) cos_interfaces: FastMap<i32, CoSInterfaceRuntime>,
    pub(crate) cos_interface_order: Vec<i32>,
    pub(crate) cos_interface_rr: usize,
    pub(crate) cos_nonempty_interfaces: usize,
    /// #1240: cumulative worker-owned v8 queue-lease acquire calls
    /// observed while draining this binding's CoS queues.
    pub(crate) cos_queue_lease_acquire_v8_calls: u64,
    /// #1240: cumulative bytes granted by v8 queue-lease acquire calls.
    pub(crate) cos_queue_lease_acquire_v8_granted_bytes: u64,
}
