//! #959 Phase 6 — extracts the per-binding timing / wake-pacing
//! fields out of `BindingWorker` into a dedicated `WorkerTimers`
//! sub-struct.
//!
//! These six fields gate per-binding pacing decisions: when to
//! send a TX wake-up syscall (last_tx_wake_ns), when to RX wake
//! (last_rx_wake_ns), when to update the BPF heartbeat map
//! (last_heartbeat_update_ns), when to publish idle debug state
//! (last_idle_debug_publish_ns), and the debug-state cadence
//! counters (debug_state_counter / empty_rx_polls).
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-6. Field names preserved so
//! `binding.timers.last_rx_wake_ns` keeps the same grep-friendly
//! suffix as the original `binding.last_rx_wake_ns`.

/// Per-binding timing / wake-pacing state.
///
/// **Intentionally NOT `Default`** — for consistency with the
/// other #959 sub-structs. The legitimate construction goes through
/// the explicit literal in `BindingWorker::create` which seeds the
/// timestamps with `init_now` (a single sampled `monotonic_nanos()`
/// at worker construction); a derived Default would seed with 0,
/// causing the first heartbeat / RX-wake / TX-wake decisions to
/// immediately fire as if the binding had been idle since epoch.
pub(crate) struct WorkerTimers {
    pub(crate) last_heartbeat_update_ns: u64,
    pub(crate) debug_state_counter: u32,
    pub(crate) last_idle_debug_publish_ns: u64,
    pub(crate) last_rx_wake_ns: u64,
    pub(crate) last_tx_wake_ns: u64,
    pub(crate) empty_rx_polls: u32,
}
