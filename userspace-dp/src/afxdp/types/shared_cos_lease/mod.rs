// #1035 P4: shared CoS lease + MQFQ V_min coordination types.
//
// #2158 (P2): this module was a single ~2121-LOC file. It is now a thin
// shell that wires four cohesive submodules; the split is pure
// code-motion (no logic change). The boundaries:
//   * `backlog`  — interface-global exact-backlog visibility
//                  (`SharedCoSExactBacklog` + residual-surplus bucket).
//                  Self-contained; no visibility widening.
//   * `vtime`    — cross-worker MQFQ V_min floor (`PaddedVtimeSlot`,
//                  `SharedCoSQueueVtimeFloor`). Self-contained; no
//                  visibility widening.
//   * `epoch`    — #1229 Phase 6 v8 epoch state (`V8State`,
//                  `SharedCoSEpochState`, `PackedEpochGrant`, the v8
//                  enums + consts, equal-flow suppress state). Carries
//                  the minimal `pub(super)` widening the lease/rotation/
//                  publish siblings need to reach its fields across the
//                  new file boundary (documented at each item in
//                  `epoch.rs`).
//   * `lease`    — the `SharedCoS{Queue,Root}Lease` token bucket + the
//                  v8 per-worker fair-share acquire path + free helpers.
//                  Two fields (`config`, `v8`) widen to `pub(super)` for
//                  the rotation sibling.
//
// The two already-extracted v8 rotation siblings (`rotate_epoch_v8`,
// `publish_equal_flow_epoch_v8`, PR #1588) keep their existing wiring;
// they now reach the epoch types via the `pub(super)` widening in
// `epoch.rs` rather than the parent-module visibility they had when
// those types lived in this file.

use super::*;

mod backlog;
mod epoch;
mod lease;
mod vtime;

// Re-export the lease/vtime/backlog surface at module scope so the
// existing `types/mod.rs` re-export (`pub(super) use
// shared_cos_lease::{...}`) and the sibling submodules' `use super::*;`
// continue to resolve every symbol exactly as before the split.
pub(in crate::afxdp) use backlog::{ExactDemandQueueMask, SharedCoSExactBacklog};
pub(in crate::afxdp) use lease::{SharedCoSQueueLease, SharedCoSRootLease};
pub(in crate::afxdp) use vtime::{NOT_PARTICIPATING, PaddedVtimeSlot, SharedCoSQueueVtimeFloor};

// `pub(super)` lease internals reached only by the co-located `tests`
// module. Imported PRIVATELY into module scope so the `#[path]`-nested
// test child's `use super::*;` resolves them; not part of the
// afxdp-facing surface.
#[cfg(test)]
#[allow(unused_imports)]
use lease::{
    SharedCoSLeaseConfig, SharedCoSLeaseState, pack_shared_cos_lease_credits,
    record_equal_flow_active_sample, refill_shared_cos_lease_state,
    unpack_shared_cos_lease_credits,
};

// The v8 enums are part of the lease's public-to-afxdp surface
// (`types/mod.rs` re-exports `AcquireV8ShortfallCause` / `V8RateMode`);
// `V8EqualFlowFailOpenReason` is consumed within afxdp via the lease
// accessor return type. Re-export them at module scope.
pub(in crate::afxdp) use epoch::{AcquireV8ShortfallCause, V8EqualFlowFailOpenReason, V8RateMode};

// `pub(super)` epoch internals reached by the lease/rotation siblings and
// the co-located `tests` module. Imported PRIVATELY into this module's
// namespace (not re-exported — these stay internal to `shared_cos_lease`)
// so the siblings'/tests' `use super::*;` resolves them by name. They
// live in `epoch.rs`, a sibling of those modules, whose `pub(super)`
// items are visible throughout `shared_cos_lease` and its descendants.
#[allow(unused_imports)]
use epoch::{
    CARRY_DRAIN_MAX_EPOCHS, CARRY_MAX_EPOCHS, EPOCH_DURATION_NS, EQUAL_FLOW_MIN_WORKER_UTIL_DEN,
    EQUAL_FLOW_MIN_WORKER_UTIL_NUM, EQUAL_FLOW_VALID_STREAK_REQUIRED, MAX_ROLLBACK_RETRIES,
    MAX_ROTATION_LAG_EPOCHS, MAX_SEQ_SPINS, PackedEpochGrant, PaddedAtomicU32, PaddedAtomicU64,
    STALL_THRESHOLD_EPOCHS, SharedCoSEpochState, V8EqualFlowSuppressState, V8RotationScratch,
    V8State,
};

// Issue #1329 / PR #1588: hot-path epoch rotation submodules. Pure
// code-motion extract of maybe_rotate_epoch_v8 and
// publish_equal_flow_epoch_v8; bodies are byte-identical to the
// pre-split form, with three forced edits at the move boundary:
// visibility widens to pub(super), #[inline] is added as a hint,
// and rotate_epoch_v8.rs adds an explicit
// `use super::publish_equal_flow_epoch_v8::publish_equal_flow_epoch_v8;`
// so the rotation's call into the equal-flow helper resolves
// across the sibling-submodule boundary.
mod publish_equal_flow_epoch_v8;
mod rotate_epoch_v8;

#[cfg(test)]
#[path = "shared_cos_lease_tests.rs"]
mod tests;
