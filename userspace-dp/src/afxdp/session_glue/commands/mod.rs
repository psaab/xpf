//! Per-`WorkerCommand`-variant handlers. The dispatcher in
//! `session_glue/mod.rs` matches on `WorkerCommand` and delegates the
//! five non-trivial variants here; the three trivial variants
//! (`UpsertLocal`, `EnqueueShapedLocal`, `VacateAllSharedExactSlots`)
//! stay inline in the dispatcher because lifting 1-3 lines to a
//! sibling file is negative value (per #1346 plan v2).
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
// Fence-invariant cell (deferred-absent issues no BPF): direct access to
// the guard; production callers use the wrappers above.
#[cfg(test)]
pub(in crate::afxdp::session_glue) use delete_synced::handle_delete_synced_with_guard;
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
pub(in crate::afxdp::session_glue) use refresh_owner_rgs::collect_refresh_owner_rgs_items;
