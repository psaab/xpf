# userspace-dp/src/afxdp/types/

Shared type definitions for the AF_XDP dataplane. Every long-lived
struct that crosses module boundaries lives here so siblings can
import them without circular module dependencies.

The type tree combines shared data definitions with behavior-bearing
coordination code. `session_index.rs` implements the HA shared-session
indexes (`SharedNatAmbiguityIndex`, `SharedSessionBareTupleIndex`, and
`SharedSessionOwnerRgIndexes`) and their ambiguity/owner-scope operations.
`mod.rs` provides top-level type and re-export wiring. `shared_cos_lease/`
also owns the hot-path lease acquisition / release / epoch-rotation
algorithm (tag-checked CAS, two-CAS-with-rollback) for the shared CoS
lease. Visibility is deliberately narrower there: its items are
re-exported with `pub(super)` (afxdp-internal only), while the cos /
forwarding / tx / runtime sub-modules use `pub(in crate::afxdp)` globs.

## Files

| File | Purpose |
|------|---------|
| `cos.rs` | CoS shaper / queue / flow-fair / runtime types (`CoSInterfaceRuntime`, `CoSQueueRuntime`, `CoSPendingTxItem`, `FlowFairState`, `WorkerCoSQueueFastPath`, etc.). Issue 68.1 split. |
| `forwarding/binding.rs` | `BindingIdentity`, `WorkerBindingLookup`. |
| `forwarding/disposition.rs` | `ForwardingDisposition`, `RouteIdentity`, `ForwardingLookupResult`, `ForwardingResolution`. |
| `forwarding/fabric.rs` | `FabricLink`, `FabricSkipReason`, `FabricLinkSkip`. |
| `forwarding/fib.rs` | Route / connected / leak / ECMP next-hop types, `MirrorRuntimeConfig`, `NeighborEntry`. |
| `forwarding/local.rs` | `EgressInterface`. |
| `forwarding/mod.rs` | Routing / forwarding type declarations and submodule wiring (#16209); re-exports preserved visibility surfaces from `types/mod.rs`. |
| `forwarding/state.rs` | `ForwardingState` definition and implementation, paired-insert tests, `SynCookieMasterKey`, `InstallTables`, `FabricNatScopeIdentity`. |
| `forwarding/tunnels.rs` | `TunnelEndpoint`, `WgRuntimePeer`. |
| `forwarding/zones.rs` | `ZoneHostInbound`, `is_host_inbound_multicast_group`. |
| `mod.rs` | Top-level type wiring, packet metadata/session types, and re-exports. |
| `runtime.rs` | Per-worker runtime atomics and shared status types. |
| `runtime_view.rs` | `RuntimeView` — atomically-published paired validation and forwarding state (#6592). |
| `session_index.rs` | HA shared-session index types and implementations (`SharedNatAmbiguityIndex`, `SharedSessionBareTupleIndex`, `SharedSessionOwnerRgIndexes`), moved from `mod.rs`. |
| `shared_cos_lease/backlog.rs` | Interface-global exact-backlog visibility and residual-surplus token bucket. |
| `shared_cos_lease/epoch.rs` | V8 lease-rotation epoch state, grant packing, and related enums/constants. |
| `shared_cos_lease/lease.rs` | Shared CoS queue/root leases, token-bucket state, and v8 fair-share acquisition. |
| `shared_cos_lease/mod.rs` | Wiring and re-exports for the shared-CoS backlog, epoch, lease, and virtual-time modules (#1035 P4, #2158). |
| `shared_cos_lease/publish_equal_flow_epoch_v8.rs` | Conditional equal-flow-suppression publish branch of v8 epoch rotation. |
| `shared_cos_lease/rotate_epoch_v8.rs` | `SharedCoSQueueLease::maybe_rotate_epoch_v8` — v8 epoch-rotation state machine. |
| `shared_cos_lease/vtime.rs` | Cross-worker MQFQ V_min floor (`PaddedVtimeSlot`, `SharedCoSQueueVtimeFloor`). |
| `tx.rs` | TX request / prepared-request shapes (`TxRequest`, `PreparedTxRequest`, etc.). |

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
  `pub(in crate::afxdp) use runtime::*;`. It also re-exports the HA
  indexes from `session_index.rs` and keeps the narrower
  `pub(super) use shared_cos_lease::{...}`. A
  `pub(crate) use forwarding::{ForwardingDisposition, ForwardingResolution}` for
  callers in `crate::*` outside `afxdp/`, and the widest one,
  `pub use forwarding::NeighborEntry`, used by `server/handlers/neighbors.rs`
  to construct `afxdp::NeighborEntry` from outside the module.
