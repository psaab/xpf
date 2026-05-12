//! #959 Phase 1 — extracts the `dbg_*` debug counters out of
//! `BindingWorker` into a dedicated `WorkerTelemetry` sub-struct.
//!
//! Pure structural extraction: no semantic change, no alignment hint,
//! no field reordering beyond what's necessary to hold the 23
//! counters in a coherent group. Phase 2+ may add `#[repr(align(64))]`
//! once the cache-line layout is profiled.

/// Per-worker debug telemetry counters incremented from the
/// data-plane hot path. Read sites (formatting, max-window
/// comparison) are minimal and confined to the per-second debug
/// tick; see `worker/lifecycle.rs` and `tx/rings.rs`.
///
/// Field semantics are documented at each callsite in the worker
/// implementation; this struct preserves the names verbatim so that
/// existing log lines, gRPC snapshot fields, and operator runbooks
/// continue to work.
#[derive(Debug, Default)]
pub(crate) struct WorkerTelemetry {
    pub(crate) dbg_fill_submitted: u64,
    pub(crate) dbg_fill_failed: u64,
    pub(crate) dbg_poll_cycles: u64,
    pub(crate) dbg_backpressure: u64,
    pub(crate) dbg_rx_empty: u64,
    pub(crate) dbg_rx_wakeups: u64,
    // TX pipeline debug counters
    pub(crate) dbg_tx_ring_submitted: u64,
    pub(crate) dbg_tx_ring_full: u64,
    pub(crate) dbg_completions_reaped: u64,
    pub(crate) dbg_tx_completion_ring_available: u32,
    pub(crate) dbg_tx_completion_ring_available_max: u32,
    pub(crate) dbg_sendto_calls: u64,
    pub(crate) dbg_sendto_err: u64,
    pub(crate) dbg_sendto_eagain: u64,
    pub(crate) dbg_sendto_enobufs: u64,
    // #802/#804: per-binding bound-pending / CoS overflow counters
    pub(crate) dbg_bound_pending_overflow: u64,
    pub(crate) dbg_cos_queue_overflow: u64,
    pub(crate) dbg_tx_tcp_rst: u64,
    // Ring diagnostics — raw values from xsk_ffi
    pub(crate) dbg_rx_avail_nonzero: u64,
    pub(crate) dbg_rx_avail_max: u32,
    pub(crate) dbg_fill_pending: u32,
    pub(crate) dbg_device_avail: u32,
    pub(crate) dbg_rx_wake_sendto_ok: u64,
    pub(crate) dbg_rx_wake_sendto_err: u64,
    pub(crate) dbg_rx_wake_sendto_errno: i32,
}
