# userspace-dp/src/afxdp/types/

Shared type definitions for the AF_XDP dataplane. Every long-lived
struct that crosses module boundaries lives here so siblings can
import them without circular module dependencies.

Most files are definitions only, but `shared_cos_lease.rs` is an
exception: it owns the hot-path lease acquisition / release / epoch
rotation algorithm (tag-checked CAS, two-CAS-with-rollback) for the
shared CoS lease. That algorithm lives with the type because it's
the contract for safe coordination across workers; siblings reach
into it through the `pub(in crate::afxdp)` re-exports below.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub for the per-area type files below. |
| `cos.rs` | CoS shaper / queue / flow-fair / runtime types (`CoSInterfaceRuntime`, `CoSQueueRuntime`, `CoSPendingTxItem`, `FlowFairState`, `WorkerCoSQueueFastPath`, etc.). Issue 68.1 split. |
| `forwarding.rs` | Routing / forwarding types (`ForwardingResolution`, `ForwardingDisposition`, `PacketDisposition`, `ValidationState`, etc.). Issue 68.2 split. Three forwarding types had wider-than-`pub(super)` visibility in the original `mod.rs` and stay re-exported at their original surface. |
| `runtime.rs` | Per-worker runtime atomics and shared status types. |
| `shared_cos_lease.rs` | Shared per-CoS lease + V_min coordination types (#1035 P4): `SharedCoSQueueLease`, `SharedCoSRootLease`, `SharedCoSQueueVtimeFloor`, `PaddedVtimeSlot`, `NOT_PARTICIPATING` sentinel. |
| `tx.rs` | TX request / prepared-request shapes (`TxRequest`, `PreparedTxRequest`, etc.). |
| `shared_cos_lease_tests.rs` | Unit tests for the V_min lease coordination — pinned because the lease is the load-bearing primitive in #1229 v8. |

## Notable

- The shared-CoS-lease types are how `worker/` cooperates *without*
  cross-worker writes — readers compute against the floor; only the
  V_min owner advances it. See `docs/per-5-tuple/state.md` for why
  this matters for fairness mechanism design.
- The `mod.rs` re-exports are explicit per-sub-module globs:
  `pub(in crate::afxdp) use cos::*;`,
  `pub(in crate::afxdp) use forwarding::*;`,
  `pub(in crate::afxdp) use tx::*;`,
  `pub(in crate::afxdp) use runtime::*;`. Plus a narrower
  `pub(super) use shared_cos_lease::{...}` and a wider
  `pub(crate) use forwarding::{ForwardingDisposition, ForwardingResolution}`
  for the two forwarding types that have callers outside `afxdp/`.
