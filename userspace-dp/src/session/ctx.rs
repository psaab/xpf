//! Context structs used by `super::SessionTable`'s upsert/update fns.
//!
//! Encapsulates the previously-positional 7-field cluster so call
//! sites do not drift fields. See #1357.
//!
//! Two structs, no embedding:
//!
//! - [`SessionInstall`] carries an owned [`SessionKey`]. Used by
//!   [`super::SessionTable::upsert_synced_with_origin`] (with a
//!   positional `allow_replace_local: bool`). The install fn
//!   `install_with_protocol_with_origin` itself stays positional —
//!   see plan "Rollback execution" — but its `upsert_synced` sibling
//!   takes this struct.
//! - [`SessionUpdate`] carries a borrowed `&'a SessionKey`. Used by
//!   [`super::SessionTable::update_session`] (with a positional
//!   `ha_activation: bool`) and
//!   [`super::SessionTable::promote_synced_with_origin`].
//!
//! Operational control flags (`allow_replace_local`, `ha_activation`)
//! intentionally stay positional — they are *not* part of the
//! session payload and embedding them inside the struct would force
//! callers to populate fields the callee may overwrite.

use super::entry::{SessionDecision, SessionMetadata, SessionOrigin};
use super::key::SessionKey;

/// Owned identity + payload + timing for a fresh session insert or a
/// peer-synced upsert (where the caller has just constructed the
/// key).
#[derive(Debug, Clone)]
pub(crate) struct SessionInstall {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) now_ns: u64,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
    /// #5212: the ORIGINATING node's stable RT_FLOW session id, carried across
    /// the HA session-sync wire so a peer-synced session ADOPTS the peer's id
    /// rather than minting a fresh node-local one — making the SESSION_CREATE
    /// (emitted on the origin node) and the SESSION_CLOSE (which may be emitted
    /// on the peer after a failover) share one correlatable id across both
    /// nodes. 0 means "no id carried" (a legacy peer that predates the wire
    /// field, or a locally-generated upsert such as a tunnel replica): the
    /// receiver falls back to `alloc_session_id()` (pre-#5212 behavior,
    /// rolling-upgrade safe). Only `upsert_synced_with_origin` consults it.
    pub(crate) session_id: u64,
    /// #9412: the TCP close class a peer stated for this session on the HA wire
    /// (`0` = open or not carried). Only `upsert_synced_with_origin` consults it.
    pub(crate) tcp_close_class: u8,
}

/// In-place update or promotion of an existing session. Carries a
/// borrowed `&'a SessionKey` because the caller already owns the
/// key on the surrounding update/promote path; cloning it into a
/// [`SessionInstall`] would force an unnecessary owned copy at
/// production call sites such as `session_glue/mod.rs:1071`.
///
/// Does NOT carry the `ha_activation` flag — that is a control
/// argument to `update_session`, not part of the data payload.
/// `promote_synced_with_origin` hides the flag by calling
/// `update_session(req, false)`.
#[derive(Debug, Clone)]
pub(crate) struct SessionUpdate<'a> {
    pub(crate) key: &'a SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) now_ns: u64,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
}

/// #2120: per-call HA context handed to the expire pass so the
/// timer-wheel GC can HOLD peer-synced sessions this node does not
/// forward (restoring the dead Go-GC `IsLocalPrimary` retention
/// contract), self-heal them on RG promotion, and reap them at a
/// bounded ceiling if a primary delete is lost.
///
/// The HA-forwarding logic itself lives on the `afxdp` side (the
/// `HAGroupRuntime` lease predicate is `pub(in crate::afxdp)` and must
/// not leak into `crate::session`), so the caller supplies it as
/// borrowed closures:
///
/// - `forwards_rg(rg)` answers "does this node currently FORWARD the
///   session whose `owner_rg_id == rg`?" — for `rg > 0` it is the
///   per-RG `is_forwarding_active` predicate; for `rg <= 0` it is the
///   node-level "forwards any RG" predicate (`node_active`).
/// - `epoch_of(rg)` reads the RG epoch counter with the
///   `< MAX_RG_EPOCHS` index guard, falling back to the node-level
///   `rg_epochs[0]` for any `rg` that is not a valid per-RG index — both
///   `rg <= 0` AND an out-of-range `rg` map to `rg_epochs[0]` (the
///   node-level activation edge that lets the self-heal fire for
///   `owner_rg_id == 0` fabric/reverse entries, and that keeps a
///   corrupt/out-of-range RG from silently pinning epoch 0). The exact
///   fallback for out-of-range RG is caller-defined; the worker's
///   `epoch_of` implements this `rg_epochs[0]` behavior.
///
/// `node_active` is hoisted once per expire call (true iff this node
/// forwards at least one RG, i.e. it is a real, currently-forwarding
/// cluster node) and is the "are we in a cluster that owns anything"
/// guard that keeps a STANDALONE node from ever holding.
pub(crate) struct ExpireHaContext<'a> {
    /// True iff this node currently forwards at least one RG. Gates the
    /// HOLD so a standalone / fully-standby-but-non-cluster node never
    /// retains. Hoisted once per `expire_stale_entries` call.
    pub(crate) node_active: bool,
    /// Per-RG forwarding predicate (see struct docs). `rg <= 0` maps to
    /// `node_active`.
    pub(crate) forwards_rg: &'a dyn Fn(i32) -> bool,
    /// RG epoch reader (see struct docs). Any `rg` that is not a valid
    /// per-RG index (`rg <= 0` OR out of range) maps to the node-level
    /// `rg_epochs[0]`.
    pub(crate) epoch_of: &'a dyn Fn(i32) -> u32,
    /// Stale-synced ceiling multiplier: a held entry is reaped once it
    /// has been held longer than `min(mult × expires_after_ns, abs_ns)`.
    pub(crate) ceiling_mult: u64,
    /// Stale-synced ceiling absolute cap (ns). Bounds the pathological
    /// long-timeout (`MaxDurationSeconds`) config so a leaked entry
    /// cannot be pinned for the full configured timeout.
    pub(crate) ceiling_abs_ns: u64,
}

impl ExpireHaContext<'_> {
    /// `min(mult × timeout, abs_cap)` — the maximum time an entry may
    /// remain HELD before the lost-delete reaper removes it. `mult == 0`
    /// is treated as "no relative ceiling" (the abs cap still applies)
    /// so a misconfigured 0 cannot reap held entries immediately.
    #[inline]
    pub(crate) fn stale_ceiling_ns(&self, expires_after_ns: u64) -> u64 {
        let relative = expires_after_ns.saturating_mul(self.ceiling_mult);
        if relative == 0 {
            self.ceiling_abs_ns
        } else {
            relative.min(self.ceiling_abs_ns)
        }
    }
}
