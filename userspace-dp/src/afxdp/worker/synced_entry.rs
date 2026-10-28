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
    /// Ordinary source-NAT origin carried across the HA session-sync wire.
    pub(crate) source_nat_static: Option<bool>,
    /// #9951: exact inter-VRF leak incarnation used by the cached resolution.
    /// This is an in-process worker/shared-map stamp, not HA wire data; a peer
    /// import re-resolves locally before forwarding.
    pub(crate) leak_incarnation: u64,
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
    /// promote) leave this 0: the incremental Open delta carries the real id
    /// straight off the live entry
    /// (`install_with_protocol_with_origin`), and a 0 here on any import path
    /// falls back to `alloc_session_id()` (rolling-upgrade safe). #14667:
    /// synthesized reverse companions are the exception — the HA-import
    /// synthesizer derives one deterministic companion id from the
    /// forward's stable id (`synthesized_companion_session_id`, reserved
    /// `0xFFFE` namespace) and the live-reply synthesizer publishes the id
    /// it just minted, so every worker adopts ONE companion identity and
    /// the identity-captured policy delete cannot miss on siblings.
    pub(crate) session_id: u64,
    /// #9412: the session's TCP close class on the HA wire (`0` = open or not
    /// carried), from `SessionSyncRequest.tcp_close_class` on a peer import.
    /// `upsert_synced_with_origin` applies it. Local publishes carry `0`.
    pub(crate) tcp_close_class: u8,
    /// #10888: the owning node's TCP handshake state (`0` = legacy/established).
    /// `upsert_synced_with_origin` applies it independently of close class.
    pub(crate) tcp_handshake_state: u8,
    /// #16217 (export stamp) + #16019 fold 2: actual reverse-direction
    /// packets the serving node has forwarded for this tuple,
    /// snapshotted onto the shared row at publish/restamp time from
    /// the live forward entry's admitted `counters.rev_packets`
    /// (`rev_packets_wire_for`). Synced rows otherwise carry no
    /// counters, so this is the only node-wide reverse-service
    /// evidence `shared_completion_evidence` and the pressure-shed
    /// shared fence (`shared_session_replied`) may read. A synthesized
    /// reverse companion is published with 0 here; mere existence
    /// proves nothing. Never set from a handshake wire.
    pub(crate) rev_packets: u64,
    /// #16217 (adoption evidence): actual forward-direction packets
    /// the serving node has admitted for this tuple, snapshotted
    /// alongside `rev_packets`. Synced rows otherwise carry no
    /// counters; the fabric-adoption gate reads this (with
    /// `rev_packets`) only for a `HandshakePending` row, so a
    /// zero-traffic pending row never qualifies. Monotonic per
    /// incarnation at publish, exactly like `rev_packets`.
    pub(crate) fwd_packets: u64,
    /// #14303: the PPTP call-id pair (`PptpCall::to_wire_call_ids`) for a
    /// `Pptp(handle)` forward session, `PPTP_CALL_IDS_ABSENT` (0) otherwise.
    /// Carried on the shared entry so the coordinator bulk export and the
    /// tunnel-remap purge — which iterate the shared map and have no worker
    /// `SessionTable` association table to consult — can stamp the same pair
    /// the incremental producers stamp via `pptp_call_ids_wire_for`. Set from
    /// the verified wire pair at HA import; local publishes leave 0 because
    /// the owning worker stamps its own Open delta from its live table, and
    /// this entry's pair is only read when re-exporting a peer-originated
    /// session this node adopted.
    pub(crate) pptp_call_ids: u64,
    /// #16615/#17683: exact persistent lease allocator/incarnation hold.
    pub(crate) persistent_lease_hold: Option<crate::nat::PersistentLeaseHold>,
}

impl crate::session::SessionDelta {
    /// #17122 (R4-Q05-02): THE mapping from a shared `SyncedSessionEntry`
    /// to a `SessionDelta` — the single construction the HA bulk export
    /// (Open) and the tunnel-remap purge (Close) both go through.
    ///
    /// This exists because the two call sites previously hand-wrote the
    /// same 21-field literal, and both copies shipped HA bugs when a
    /// field changed: #14303 (`pptp_call_ids: 0` withheld PPTP sessions
    /// on failover-after-resync) and #14960 (`fabric_redirect_sync:
    /// true` + `session_id: 0` on every bulk-exported plain session).
    /// The compiler only forces that a value is present, not that it is
    /// the right one, so every carried field is read from `entry` here
    /// and nowhere else: a new `SessionDelta` field fails compilation
    /// until this constructor sets it (entry constructors elsewhere
    /// must still populate any new `SyncedSessionEntry` field).
    ///
    /// Carried from the entry: `key`, `decision`, `metadata`,
    /// `source_nat_static`, `origin`, `session_id`, `tcp_close_class`,
    /// `tcp_handshake_state`, `pptp_call_ids`, and the packet counters
    /// (`fwd_packets`/`rev_packets`; the shared row snapshots no byte
    /// counts, so both byte legs stay 0). `fabric_redirect_sync` is
    /// derived from the disposition in this one place — exactly as both
    /// encoder legs compute `fabric_redirect_sync || disposition ==
    /// FabricRedirect` (#14960).
    ///
    /// No-local-snapshot defaults, set once here: `provenance:
    /// Incremental`, `bulk_resync: false`, `is_admission: false`,
    /// `policy_generation: 0`, `purge_retirement: false`, and
    /// `created_ns` / `last_seen_ns` / `observed_tos` /
    /// `observed_tcp_flags` all 0/unknown — the shared entry carries no
    /// creation instant, no observed ToS/TCP flags, and these deltas
    /// are not routed through the RT_FLOW close exporter (#2465/#2749).
    ///
    /// Callers that need a different value for a field the entry owns
    /// override it with struct-update syntax so the deliberate
    /// divergence stays visible at the call site (the purge's
    /// `source_nat_static: None` / `fabric_redirect_sync: false`), and
    /// the bulk export restamps `tcp_handshake_state` from node-wide
    /// completion evidence after construction (#16217).
    pub(crate) fn from_shared(
        entry: &SyncedSessionEntry,
        kind: crate::session::SessionDeltaKind,
    ) -> Self {
        Self {
            provenance: crate::session::ExportProvenance::Incremental,
            kind,
            key: entry.key.clone(),
            decision: entry.decision,
            metadata: entry.metadata.clone(),
            source_nat_static: entry.source_nat_static,
            policy_generation: 0,
            origin: entry.origin,
            fabric_redirect_sync: entry.decision.resolution.disposition
                == crate::afxdp::ForwardingDisposition::FabricRedirect,
            created_ns: 0,
            last_seen_ns: 0,
            counters: crate::session::SessionCounters {
                fwd_packets: entry.fwd_packets,
                fwd_bytes: 0,
                rev_packets: entry.rev_packets,
                rev_bytes: 0,
            },
            observed_tos: 0,
            observed_tcp_flags: 0,
            session_id: entry.session_id,
            bulk_resync: false,
            is_admission: false,
            tcp_close_class: entry.tcp_close_class,
            tcp_handshake_state: entry.tcp_handshake_state,
            pptp_call_ids: entry.pptp_call_ids,
            purge_retirement: false,
        }
    }
}

impl SyncedSessionEntry {
    /// #17058: the reverse construction — `SessionTable::synced_entry_for`
    /// builds one of these from a live table row in one lookup. Callers
    /// that hold a live row (policy-delete probe, shared promote) MUST
    /// route through it rather than hand-building a literal: a literal
    /// compiles only because every new field gets a default, and
    /// silently turns "unknown" into a value (the #12187
    /// `source_nat_static: None` divergence).
    ///
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
            source_nat_static: self.source_nat_static,
            origin: self.origin,
            now_ns,
            protocol: self.protocol,
            tcp_flags: self.tcp_flags,
            session_id: self.session_id,
            tcp_close_class: self.tcp_close_class,
            tcp_handshake_state: self.tcp_handshake_state,
            persistent_lease_hold: self.persistent_lease_hold,
            fwd_packets: self.fwd_packets,
            rev_packets: self.rev_packets,
        }
    }
}
