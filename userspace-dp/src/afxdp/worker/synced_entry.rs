//! `SyncedSessionEntry`: a session as the HA sync path and the shared session maps
//! carry it between workers, and its one mapping to an install request.
//!
//! Split out of `worker/mod.rs` by #9412. The close-class field and the install
//! constructor would have pushed that file past the 2000-LOC [REFACTOR] floor
//! (docs/engineering-style.md, "Modularity discipline"). This is pure code motion:
//! the struct and its impl are unchanged, and they are re-exported at the old
//! path, `afxdp::worker::SyncedSessionEntry`.

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct SyncedSessionEntry {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) protocol: u8,
    pub(crate) tcp_flags: u8,
    /// #2170 HA install generation, mirrored from the Go cluster apply
    /// layer. 0 means unknown/legacy. The local-origin entries (forwarding
    /// learn, tunnel, promote, etc.) leave this 0 — only SyncImport entries
    /// from the peer carry a meaningful generation, and the guards only act
    /// when BOTH the stored and incoming generations are non-zero, so
    /// local-origin entries fall back to today's unconditional behavior.
    pub(crate) generation: u64,
    /// #5212: the originating node's STABLE RT_FLOW session id (`alloc_session_id`
    /// namespace) carried across the HA session-sync wire. Populated (non-zero)
    /// only on a peer-synced FORWARD import off the wire (`build_synced_session_entry`),
    /// where it is threaded onto the imported entry so the standby ADOPTS the
    /// peer's id instead of minting a fresh local one — the standby's
    /// SESSION_CLOSE RT_FLOW then correlates with the primary's SESSION_CREATE
    /// across HA nodes. Local-origin publishes (forwarding learn, tunnel,
    /// promote) and synthesized reverse companions leave this 0: the incremental
    /// Open delta carries the real id straight off the live entry
    /// (`install_with_protocol_with_origin`), and a 0 here on any import path
    /// falls back to `alloc_session_id()` (rolling-upgrade safe).
    pub(crate) session_id: u64,
    /// #9412: the session's TCP close class on the HA wire (`0` = open or not
    /// carried), from `SessionSyncRequest.tcp_close_class` on a peer import.
    /// `upsert_synced_with_origin` applies it. Local publishes carry `0`.
    pub(crate) tcp_close_class: u8,
}

impl SyncedSessionEntry {
    /// #9412: THE mapping from a synced entry to an install request, used by the
    /// two installers that take a synced entry as-is and by the #9412
    /// acceptance fixture. A field dropped here (such as the close class this
    /// issue carries) is dropped for all of them at once, so the acceptance
    /// cells see it. A hand-built literal in the fixture could not.
    ///
    /// Consumes `self` and moves every field, exactly like the literals it
    /// replaces: no clone, and no policy-counter `Arc` bump on the import path.
    /// `generation` is not part of an install and is dropped, as before.
    pub(crate) fn into_session_install(self, now_ns: u64) -> crate::session::SessionInstall {
        crate::session::SessionInstall {
            key: self.key,
            decision: self.decision,
            metadata: self.metadata,
            origin: self.origin,
            now_ns,
            protocol: self.protocol,
            tcp_flags: self.tcp_flags,
            session_id: self.session_id,
            tcp_close_class: self.tcp_close_class,
        }
    }
}
