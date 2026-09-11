//! #959 Phase 5 — extracts the per-binding BPF map file descriptors
//! out of `BindingWorker` into a dedicated `WorkerBpfMaps` sub-struct.
//!
//! These four FDs are opened once at binding construction (from the
//! coordinator's pinned BPF map paths) and used through the binding's
//! lifetime for: heartbeat updates (per-second), session table
//! deltas (per-RX-batch), and conntrack v4/v6 lookups during fast-
//! path session resolution.
//!
//! Pure structural extraction: capacities and access semantics
//! unchanged from master pre-Phase-5. Field names preserved so
//! `binding.bpf_maps.heartbeat_map_fd` keeps the same grep-friendly
//! suffix as the original `binding.heartbeat_map_fd`.

// Use `core::ffi::c_int` to match the rest of the afxdp module which
// pulls `c_int` via `super::*` (e.g. afxdp/mod.rs, bpf_map.rs). This
// keeps the FFI integer type source consistent across the crate.
use core::ffi::c_int;

/// Per-binding BPF map file descriptors. Opened once at binding
/// construction; constant for the binding's lifetime.
///
/// **Intentionally NOT `Default`** — these are real OS-level file
/// descriptors. A `WorkerBpfMaps::default()` would silently produce
/// `c_int = 0` (which is `stdin`), which any subsequent BPF syscall
/// would treat as a valid (wrong) FD with potentially destructive
/// effects. Construction must go through the explicit literal in
/// `BindingWorker::create` which receives the FDs from the
/// coordinator's already-validated `OwnedFd` opens.
pub(crate) struct WorkerBpfMaps {
    pub(crate) heartbeat_map_fd: c_int,
    /// #9560: the steering map's fd and its row-owner registry.
    pub(crate) session_map: crate::afxdp::bpf_map::SteeringMapRef,
    pub(crate) conntrack_v4_fd: c_int,
    pub(crate) conntrack_v6_fd: c_int,
}
