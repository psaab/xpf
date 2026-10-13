//! Control request/response and snapshot schema types shared between the
//! control socket server (`main.rs`) and the AF_XDP coordinator
//! (`afxdp/` module tree).
//!
//! All types are `pub(crate)` so they are visible across the crate without
//! being part of the public API, with one historical exception:
//! `WorkerRuntimeStatus` carries `pub` visibility (preserved from before
//! the split for #869 instrumentation that surfaced it for external
//! tooling). All other types stay `pub(crate)`.
//!
//! Split (#1325) into domain submodules:
//!   - `snapshot`: config DTOs (ConfigSnapshot tree, interface/route/zone/
//!     fabric/tunnel/neighbor/mirror snapshots, MapPins, capabilities)
//!   - `cos`: CoS config (ClassOfServiceSnapshot tree) and CoS status
//!     (CoSInterfaceStatus, CoSQueueStatus, CoSActiveFlowCountStatus)
//!   - `nat`: NAT rule snapshots (SNAT/DNAT/Static/NAT64/Nptv6) and
//!     SourceNatPoolStatus
//!   - `security`: screen/firewall-filter/policer/policy snapshots and
//!     counter statuses
//!   - pmech: route-based IPsec P-MECH authority snapshot DTOs
//!   - `control`: control socket request/response, ProcessStatus,
//!     session-sync wire shapes, protocol-version consts
//!   - `binding`: BindingStatus + BindingCountersSnapshot, HAGroupStatus,
//!     QueueStatus, WorkerRuntimeStatus, ExceptionStatus,
//!     SessionDeltaInfo, plus the `u64_is_zero` skip-serializing helper
//!   - `resolution`: per-packet trace types (PacketResolution,
//!     FlowTupleStatus, FlowWorkerStatus)
//!
//! Every type is re-exported here so existing `crate::protocol::X`
//! callers and `use protocol::*;` in `main.rs` keep working unchanged.

mod binding;
mod control;
mod cos;
mod nat;
mod pmech;
mod resolution;
mod security;
pub(crate) mod session_delta_schema;
// #7160: `ProcessStatus`, split out of `control.rs` to keep it under the
// modularity floor. Re-exported below, so every existing path is unchanged.
mod status;
pub(crate) mod snapshot;

#[cfg(test)]
mod tests;

pub(crate) use binding::*;
pub(crate) use control::*;
pub(crate) use cos::*;
pub(crate) use nat::*;
pub(crate) use resolution::*;
pub(crate) use security::*;
pub(crate) use status::*;
pub(crate) use snapshot::*;

/// Deserialize a `Vec<T>` that tolerates an explicit JSON `null` as an empty
/// vector (#2214).
///
/// `#[serde(default)]` alone only supplies a value when the KEY IS ABSENT; an
/// explicit `null` is still handed to the field's `Deserialize` impl, and
/// `Vec<T>::deserialize` rejects `null` with `invalid type: null, expected a
/// sequence`. For a field on `ConfigSnapshot` (or any nested snapshot type)
/// that rejection aborts the ENTIRE `apply_snapshot` decode — the helper
/// returns an error before responding, closes the control socket, the Go side
/// sees a bare EOF, the helper stays in bootstrap (`enabled:false`), and the
/// dataplane forwards NOTHING. This is the #1961 no-transit signature.
///
/// A nil Go slice declared WITHOUT `,omitempty` marshals as JSON `null`, so any
/// such field is one un-resolvable config away from this crash (e.g. a NAT64
/// rule with an empty source-pool -> `pool_addresses:null`, or a firewall
/// filter with zero terms -> `terms:null`). Pair this null-tolerant decoder
/// with `,omitempty` (or an empty-not-nil slice) on the Go side so the wire is
/// robust across mixed-version Go/Rust pairs in BOTH directions.
pub(crate) fn null_tolerant_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    use serde::Deserialize as _;
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}
