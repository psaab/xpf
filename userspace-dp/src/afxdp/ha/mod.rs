// Re-export the `afxdp` namespace into `ha` so the `#[path]`-included
// `ha_tests` child module (which uses `use super::*`) resolves the shared HA
// types exactly as it did before this module was split into submodules. The
// per-owner submodules import `crate::afxdp::*` directly and do not rely on
// this. rustc's unused-import lint does not see the child-module re-import,
// hence the allow.
#[allow(unused_imports)]
use super::*;

mod state;
mod counter_query;
mod export;
mod session_domain;
mod session_import;
// #6785: the typed synced-import outcome and its refusal-token prefix are read
// by the control handler, so they must escape this private module.
pub use session_import::{
    SyncedImportOutcome, SYNCED_DELETE_REFUSED_PREFIX, SYNCED_IMPORT_REFUSED_PREFIX,
};
pub use self::session_domain::HA_REFRESH_NEEDS_CONTROL_SOCKET;
mod tunnel_purge;

pub(crate) use self::session_domain::{
    policy_match_from_parts, policy_tuple_from_key, policy_wire_family, HaRefreshOutcome,
    SessionDomain,
};
pub(crate) use self::export::{AllSessionsExport, OwnerRgExportWait};
#[cfg(test)]
pub(crate) use self::export::drain_export_deltas_from_workers;

#[cfg(test)]
#[path = "../ha_tests.rs"]
mod tests;

pub(crate) use counter_query::{SessionCounterQueryWait, WorkerSessionCounters};
