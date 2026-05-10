# userspace-dp/src/afxdp/types/

Shared type definitions for the AF_XDP dataplane. Every long-lived
struct that crosses module boundaries lives here so siblings can
import them without circular module dependencies.

The module is thin by design — definitions only, no algorithms.
Hot-path logic lives in `cos/`, `worker/`, `tx/`, etc., and reaches
into these types through `pub(in crate::afxdp)` re-exports.

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
- The `pub(in crate::afxdp) use *::*;` glob in `mod.rs` is
  deliberate — these types are infrastructure shared across the
  whole dataplane.
