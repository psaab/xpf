//! Per-`WorkerCommand`-variant handlers delegated from the dispatcher
//! in `session_glue/worker_commands.rs` (`apply_worker_commands`),
//! which matches on `WorkerCommand`. The dispatcher is not in
//! `session_glue/mod.rs` (that is only the module root).
//!
//! Delegated here: `DemoteOwnerRGS`, `RefreshOwnerRGS`,
//! `ExportOwnerRGSessions`, `UpsertSynced`, `DeleteSynced`,
//! `DeleteLocalControl`, `DeleteSyncedConditional`, and
//! `ProbePolicyBatch`, plus the per-item teardown inside
//! `DeletePolicyBatch` (`handle_remove_policy_item` in
//! `delete_synced.rs`). Since #18144 also delegated here:
//! `QuerySessionCounters` (`query_session_counters.rs`),
//! `ListSessionsByPolicy` (`list_sessions_by_policy.rs`),
//! `UpsertLocal` (`upsert_local.rs`), the `DeletePolicyBatch`
//! abort-fence/batch logic (`delete_policy_batch.rs`), and
//! `DeleteSyncedIfTableUnknown`
//! (`delete_synced_if_table_unknown.rs`).
//!
//! The remaining variants stay inline in the compact match in
//! `worker_command_dispatch.rs`: bounded queue/result pushes, flags,
//! and PPTP table maintenance (`EnqueueShapedLocal`,
//! `VacateAllSharedExactSlots`, and `ForgetPptp*`).
//!
//! Files intentionally omit the `apply_` prefix: the directory path
//! (`session_glue/commands/<variant>.rs`) already encodes the
//! "apply this command" context.

mod delete_policy_batch;
mod delete_synced;
mod delete_synced_if_table_unknown;
mod demote_owner_rgs;
mod export_owner_rg_sessions;
mod list_sessions_by_policy;
mod query_session_counters;
mod refresh_owner_rgs;
mod upsert_local;
pub(in crate::afxdp) mod upsert_synced;
mod worker_command_drain;
mod worker_command_helpers;

pub(in crate::afxdp::session_glue) use delete_synced::{
    handle_delete_synced, handle_delete_synced_conditional, handle_probe_policy_tuples,
    handle_remove_policy_item,
};
pub(in crate::afxdp::session_glue) use demote_owner_rgs::handle_demote_owner_rgs;
// Shared by the worker's peer/local-control delete commands and tests that
// exercise the delete origin directly.
pub(in crate::afxdp::session_glue) use delete_policy_batch::handle_delete_policy_batch;
pub(in crate::afxdp::session_glue) use delete_synced::{
    DeleteOrigin, handle_delete_synced_with_guard,
};
pub(in crate::afxdp::session_glue) use delete_synced_if_table_unknown::handle_delete_synced_if_table_unknown;
pub(in crate::afxdp::session_glue) use export_owner_rg_sessions::handle_export_owner_rg_sessions;
pub(in crate::afxdp::session_glue) use list_sessions_by_policy::handle_list_sessions_by_policy;
pub(in crate::afxdp::session_glue) use query_session_counters::handle_query_session_counters;
pub(in crate::afxdp::session_glue) use refresh_owner_rgs::handle_refresh_owner_rgs;
pub(in crate::afxdp::session_glue) use upsert_local::handle_upsert_local;
pub(in crate::afxdp::session_glue) use upsert_synced::handle_upsert_synced;
pub(super) use worker_command_dispatch::{WorkerCommandDispatchContext, dispatch_worker_commands};
pub(in crate::afxdp::session_glue) use worker_command_drain::take_worker_command_slice;
pub(in crate::afxdp::session_glue) use worker_command_helpers::{
    handle_delete_local_control_command, handle_delete_synced_conditional_command,
    handle_demote_owner_rgs_command, handle_install_pptp_association, handle_install_pptp_call,
    handle_delete_policy_batch_command, handle_refresh_owner_rgs_command, handle_upsert_synced_command,
};
mod worker_command_dispatch;

// #4805: the activation-refresh path computes the per-session
// `allow_replace_local` inside `collect_refresh_owner_rgs_items`. Re-export it
// for the session-glue unit tests so the standby-vs-active publish decision
// can be asserted without a live BPF session-map fd (unprivileged `cargo test`
// cannot create BPF maps). Production reaches it in-file via
// `handle_refresh_owner_rgs`, so the re-export is test-only.
#[cfg(test)]
pub(in crate::afxdp) use refresh_owner_rgs::collect_refresh_owner_rgs_items;
