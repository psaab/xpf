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
//! `delete_synced.rs`).
//!
//! The remaining variants stay inline in `apply_worker_commands`.
//! Some are one-line pushes, flag sets, or PPTP table calls
//! (`EnqueueShapedLocal`, `VacateAllSharedExactSlots`, the
//! `ForgetPptp*` arms); others are larger arms with no `commands/`
//! handler today (`QuerySessionCounters`, `ListSessionsByPolicy`,
//! `UpsertLocal`, the `DeletePolicyBatch` abort-fence/batch logic,
//! `DeleteSyncedIfTableUnknown`'s purge predicate, and the PPTP
//! install arms). Do not assume an inline arm is 1-3 lines; measure
//! `worker_commands.rs` before citing a size.
//!
//! Files intentionally omit the `apply_` prefix: the directory path
//! (`session_glue/commands/<variant>.rs`) already encodes the
//! "apply this command" context.

mod delete_synced;
mod demote_owner_rgs;
mod export_owner_rg_sessions;
mod refresh_owner_rgs;
pub(in crate::afxdp) mod upsert_synced;

pub(in crate::afxdp::session_glue) use delete_synced::{
    handle_delete_synced, handle_delete_synced_conditional, handle_probe_policy_tuples,
    handle_remove_policy_item,
};
pub(in crate::afxdp::session_glue) use demote_owner_rgs::handle_demote_owner_rgs;
// Shared by the worker's peer/local-control delete commands and tests that
// exercise the delete origin directly.
pub(in crate::afxdp::session_glue) use delete_synced::{DeleteOrigin, handle_delete_synced_with_guard};
pub(in crate::afxdp::session_glue) use export_owner_rg_sessions::handle_export_owner_rg_sessions;
pub(in crate::afxdp::session_glue) use refresh_owner_rgs::handle_refresh_owner_rgs;
pub(in crate::afxdp::session_glue) use upsert_synced::handle_upsert_synced;

// #4805: the activation-refresh path computes the per-session
// `allow_replace_local` inside `collect_refresh_owner_rgs_items`. Re-export it
// for the session-glue unit tests so the standby-vs-active publish decision
// can be asserted without a live BPF session-map fd (unprivileged `cargo test`
// cannot create BPF maps). Production reaches it in-file via
// `handle_refresh_owner_rgs`, so the re-export is test-only.
#[cfg(test)]
pub(in crate::afxdp) use refresh_owner_rgs::collect_refresh_owner_rgs_items;
