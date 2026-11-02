//! Owner-RG session-export paging wire shapes (#9344/#9856), including the
//! #18752 client-chosen window id a page-1 kick carries so the window can be
//! abandoned even when page 1's response was lost. Split out of `control.rs`
//! to keep it under the modularity floor; re-exported from `protocol` so every
//! existing `crate::protocol::X` caller is unchanged.

use serde::{Deserialize, Serialize};

/// #9344/#9856: the owner-RG session export paging contract this helper
/// implements.
///
/// Version 2 adds an explicit request marker, a nonzero helper incarnation,
/// a sequence echo, and a per-window dropped count. Both sides fail closed
/// when any of those fields are absent or inconsistent; v1 helpers are not
/// safe to page because they silently truncate at `max`.
pub(crate) const SESSION_EXPORT_PAGING_PROTOCOL_VERSION: i32 = 2;
static SESSION_EXPORT_INCAR: std::sync::LazyLock<u64> =
    std::sync::LazyLock::new(crate::hot_hash_seed::os_random_seed_u64);

/// #9856: one nonzero incarnation for this helper process. The status
/// advertisement and every export response must use the same value, while a
/// helper restart gets a fresh value before sequence numbers can be reused.
pub(crate) fn session_export_incarnation() -> u64 {
    *SESSION_EXPORT_INCAR
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionExportRequest {
    #[serde(rename = "owner_rgs", default)]
    pub owner_rgs: Vec<i32>,
    #[serde(default)]
    pub max: u32,
    /// #9856: v2 marker required on every export request, including page 1.
    #[serde(rename = "session_export_paging_protocol_version", default)]
    pub protocol_version: i32,
    /// #9344/#9856: drain the remainder of the open tokenized window.
    #[serde(default)]
    pub continuation: bool,
    /// #9856: opaque helper-incarnation component of the continuation token.
    #[serde(rename = "session_export_incarnation", default)]
    pub continuation_incarnation: u64,
    /// #9856: opaque sequence component of the continuation token.
    #[serde(rename = "session_export_seq", default)]
    pub continuation_sequence: u64,
    /// #18752: a client-chosen nonzero id for the window a page-1 kick
    /// opens. The client knows it before it sends the kick, so it can
    /// abandon the window even when page 1's response (and with it the
    /// helper's token) was lost or timed out.
    #[serde(rename = "session_export_client_window", default)]
    pub client_window: u64,
}
