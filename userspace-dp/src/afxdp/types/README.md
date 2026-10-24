# userspace-dp/src/afxdp/types/

Shared type definitions for the AF_XDP dataplane. Every long-lived
struct that crosses module boundaries lives here so siblings can
import them without circular module dependencies.

Most modules are definitions only, but `shared_cos_lease/` is an
exception: it owns the hot-path lease acquisition / release / epoch
rotation algorithm (tag-checked CAS, two-CAS-with-rollback) for the
shared CoS lease. That algorithm lives with the type because it's
the contract for safe coordination across workers. Visibility is
deliberately narrower than the rest: shared_cos_lease items are
re-exported with `pub(super)` (afxdp-internal only), while the cos
/ forwarding / tx / runtime sub-modules use `pub(in crate::afxdp)`
globs.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub for the per-area type files below. |
| `cos.rs` | CoS shaper / queue / flow-fair / runtime types (`CoSInterfaceRuntime`, `CoSQueueRuntime`, `CoSPendingTxItem`, `FlowFairState`, `WorkerCoSQueueFastPath`, etc.). Issue 68.1 split. |
| `forwarding/mod.rs` | Routing / forwarding types hub (#16209 file-only split of the former `forwarding.rs`). Re-exports sibling files below via `pub(in crate::afxdp) use <sibling>::*;` plus preserved wider surfaces (`pub use fib::NeighborEntry`, `pub(crate) use disposition::{ForwardingDisposition, ForwardingResolution}`, mirrored by `types/mod.rs`). Three forwarding types had wider-than-`pub(super)` visibility in the original `mod.rs` and stay re-exported at their original surface. (`PacketDisposition` is in `mod.rs`; `ValidationState` is in `runtime.rs`.) |
| `forwarding/state.rs` | `ForwardingState` (128-field definition, intact) + impl + paired-insert tests, `SynCookieMasterKey`, `InstallTables`, `FabricNatScopeIdentity`. |
| `forwarding/fib.rs` | Route / connected / leak / ECMP next-hop types, `MirrorRuntimeConfig`, `NeighborEntry`. |
| `forwarding/local.rs` | `EgressInterface`. |
| `forwarding/tunnels.rs` | `TunnelEndpoint`, `WgRuntimePeer`. |
| `forwarding/zones.rs` | `ZoneHostInbound`, `is_host_inbound_multicast_group`. |
| `forwarding/fabric.rs` | `FabricLink`, `FabricSkipReason`, `FabricLinkSkip`. |
| `forwarding/disposition.rs` | `ForwardingDisposition`, `RouteIdentity`, `ForwardingLookupResult`, `ForwardingResolution`. |
| `forwarding/binding.rs` | `BindingIdentity`, `WorkerBindingLookup`. |
| `runtime.rs` | Per-worker runtime atomics and shared status types. |
| `shared_cos_lease/mod.rs` | Shared per-CoS lease + V_min coordination types (#1035 P4): `SharedCoSQueueLease`, `SharedCoSRootLease`, `SharedCoSQueueVtimeFloor`, `SharedCoSExactBacklog`, `PaddedVtimeSlot`, `NOT_PARTICIPATING` sentinel. `SharedCoSExactBacklog` carries queued-byte telemetry, serviceable-byte telemetry, an exact-demand queue mask, and the shared residual-surplus token bucket used to keep best-effort/non-exact surplus inside the root rate left after exact guarantees. |
| `shared_cos_lease/rotate_epoch_v8.rs` | `SharedCoSQueueLease::maybe_rotate_epoch_v8` — per-tick seqlock rotation state machine (#1229 Phase 6 v8 + #1231 v5 + #1290 v2). Extracted in #1329 as pure code motion. |
| `shared_cos_lease/publish_equal_flow_epoch_v8.rs` | `publish_equal_flow_epoch_v8` — conditional equal-flow-suppression publish branch of the rotation. Extracted in #1329 as pure code motion. |
| `tx.rs` | TX request / prepared-request shapes (`TxRequest`, `PreparedTxRequest`, etc.). |
| `shared_cos_lease/shared_cos_lease_tests.rs` | Unit tests for the V_min lease coordination — pinned because the lease is the load-bearing primitive in #1229 v8. |

## Notable

- The shared-CoS-lease types are how `worker/` cooperates *without*
  cross-worker writes — readers compute against the floor; only the
  V_min owner advances it. See `docs/per-5-tuple/state.md` for why
  this matters for fairness mechanism design.
- Equal-flow suppression follows the same ownership rule: epoch
  rotation publishes `fail_open_reason`, `fail_open_count`, and the
  enforced cap payload; acquire-side helpers are read-only against
  those fields so stale workers cannot overwrite the current epoch's
  operator-visible state. Acquire-side stale/tag mismatches use a
  separate monotonic counter because they are transient read failures,
  not a new epoch-level fail-open reason.
- The `mod.rs` re-exports are explicit per-sub-module globs:
  `pub(in crate::afxdp) use cos::*;`,
  `pub(in crate::afxdp) use forwarding::*;`,
  `pub(in crate::afxdp) use tx::*;`,
  `pub(in crate::afxdp) use runtime::*;`. Plus a narrower
  `pub(super) use shared_cos_lease::{...}`, a `pub(crate) use
  forwarding::{ForwardingDisposition, ForwardingResolution}` for
  callers in `crate::*` outside `afxdp/`, and the widest one,
  `pub use forwarding::NeighborEntry`, used by `server/handlers/neighbors.rs`
  to construct `afxdp::NeighborEntry` from outside the module.
