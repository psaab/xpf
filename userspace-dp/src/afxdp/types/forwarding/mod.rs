// Forwarding/routing types extracted from afxdp/types/mod.rs (Issue 68.2),
// split into sibling files (#16209): a file-only split moving type
// definitions behind the existing `pub(in crate::afxdp) use forwarding::*`
// glob in types/mod.rs. Zero access-site edits, zero layout change.
// This split does NOT discharge the accepted-debt obligation (see
// docs/refactoring-audit-accepted.txt) to split the ForwardingState
// definition itself — that 128-field definition stays intact in
// state.rs and still owes its own PR touching construction sites.
//
// Layout:
//   state.rs       — ForwardingState + impl + paired-insert tests,
//                    SynCookieMasterKey, InstallTables,
//                    FabricNatScopeIdentity.
//   fib.rs         — route / connected / leak / ECMP next-hop types,
//                    MirrorRuntimeConfig, NeighborEntry.
//   local.rs       — EgressInterface.
//   tunnels.rs     — TunnelEndpoint, WgRuntimePeer.
//   zones.rs       — ZoneHostInbound, is_host_inbound_multicast_group.
//   fabric.rs      — FabricLink, FabricSkipReason, FabricLinkSkip.
//   disposition.rs — ForwardingDisposition, RouteIdentity,
//                    ForwardingLookupResult, ForwardingResolution.
//   binding.rs     — BindingIdentity, WorkerBindingLookup.
//
// Visibility bill (#16209): no item widens. Every definition keeps its
// pre-split visibility (`pub(in crate::afxdp)`, `pub(crate)`, or
// `pub` for NeighborEntry); types/mod.rs keeps its three wider
// re-exports (`pub use forwarding::NeighborEntry`,
// `pub(crate) use forwarding::{ForwardingDisposition,
// ForwardingResolution}`) resolving through this module's globs.
// Each sibling does `use super::super::*` (the pre-split file's
// `use super::*` shifted one level: types::*), plus reaches sibling
// types through this module's globs, so cross-file references
// resolve exactly as they resolved within the single file.

mod binding;
mod disposition;
mod fabric;
mod fib;
mod local;
mod state;
mod tunnels;
mod zones;

pub(in crate::afxdp) use binding::*;
pub(in crate::afxdp) use disposition::*;
pub(in crate::afxdp) use fabric::*;
pub(in crate::afxdp) use fib::*;
pub(in crate::afxdp) use local::*;
pub(in crate::afxdp) use state::*;
pub(in crate::afxdp) use tunnels::*;
pub(in crate::afxdp) use zones::*;

// Wider-than-glob surfaces preserved from the pre-split file (see
// types/mod.rs:30-31, which re-exports these same names one level up).
pub use fib::NeighborEntry;
pub(crate) use disposition::{ForwardingDisposition, ForwardingResolution};
