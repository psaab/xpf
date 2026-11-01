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
use super::TcpHandshakeState;

/// Owned identity + payload + timing for a fresh session insert or a
/// peer-synced upsert (where the caller has just constructed the
/// key).
#[derive(Debug, Clone)]
pub(crate) struct SessionInstall {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    /// Ordinary source-NAT origin from the HA wire; `None` remains unknown for
    /// legacy peers and for sessions without an ordinary source translation.
    pub(crate) source_nat_static: Option<bool>,
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
    /// #10888: owning-node TCP handshake state (`0` = legacy/established).
    /// Only `upsert_synced_with_origin` consults it.
    pub(crate) tcp_handshake_state: u8,
    /// #16615/#17683: exact persistent lease key, allocator, and incarnation
    /// held by this session. None means no recorded hold.
    pub(crate) persistent_lease_hold: Option<crate::nat::PersistentLeaseHold>,
    /// #16217 (run11): the serving node's admitted per-direction packet
    /// counts carried on the HA wire / shared row (`SyncedSessionEntry`
    /// `fwd_packets`/`rev_packets`). Seeded onto the imported entry's
    /// counters (packet counts only; bytes unknown stay 0) so
    /// `forward_established_with_traffic` sees the peer's actual service
    /// instead of the zero a fresh import used to start with. Without
    /// this, a peer-imported established row was indistinguishable from
    /// a never-served row until a local packet folded onto it, and the
    /// Wire34 established guard declined to protect it. Only
    /// `upsert_synced_with_origin` consults them; 0/0 (legacy peer,
    /// local replica) seeds zero exactly as before.
    pub(crate) fwd_packets: u64,
    pub(crate) rev_packets: u64,
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
    /// #16042: parsed TCP ack of the segment driving this update, when the
    /// caller parsed a frame. `None` = unparsed (pre-#16042 flags-only
    /// behaviour, bounded by the opening window). Most callers have no
    /// frame and pass `None`; the session-hit promote path passes the
    /// ack it parsed so a wrong-ack segment cannot promote/complete. The expected ack
    /// is the companion SYN ack end (ISN + 1 + SYN payload).
    pub(crate) ack: Option<u32>,
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
    /// #16223: node-level served-handshake evidence for an idle-crossed
    /// tuple, consulted BEFORE the local `syn_ack_first` /
    /// `handshake_pending` refusals in the opening-retention arm.
    /// Production wires this to the shared synced map + serving
    /// counters (see `NodeServedEvidence`); tests drive it directly.
    pub(crate) node_served: &'a dyn Fn(&SessionKey) -> NodeServedEvidence,
}
/// #16223: node-level served-handshake evidence for one tuple — the
/// promoted serving companion's handshake wire state plus its admitted
/// reverse-packet count, consulted BEFORE the local `syn_ack_first` /
/// `handshake_pending` refusals. Production supplies the wire state
/// from the node's shared synced map (`SyncedSessionEntry`
/// `tcp_handshake_state`, restamped to Established on completion) and
/// the counter from the serving worker's per-table stamp
/// (`SessionTable::note_node_served_handshake`). A default/zero value
/// means no node-level proof, and the classic local gates then apply
/// unchanged.
/// #16217 (ct-slice HA emit): per-forward-key rate-limit state for the
/// ct-slice stage/count Update vehicle. The restamp on fw0 advances
/// its shared rows to wire=4 with `rev>0` counters, but that evidence
/// lives only in fw0's node-local shared maps — no HA delta carries
/// it (emission is transition-only and fw0's split forward half never
/// locally transitions). The ct-slice therefore queues one Update per
/// stage transition per node for each collected forward key: the
/// FIRST emit for a key at wire=4 (`Established`) and, when the row
/// is not yet at wire=4, the first emit once its counts first show
/// `rev>0`. Steady-state slices for an already-emitted key stay
/// silent (no periodic spam); a key that regresses below the emitted
/// stage (new incarnation / re-pend) re-arms. Bounded by the session
/// table's forward-row count; entries die with their session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CtSliceEmitMark {
    /// Highest handshake wire this key has emitted an Update for
    /// (0 = never; 4 = Established emitted).
    pub(crate) stage_wire: u8,
    /// Whether an Update carrying `rev>0` has been emitted for this
    /// key since it was last armed.
    pub(crate) rev_emitted: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NodeServedEvidence {
    /// Handshake wire state for the tuple (0 = absent/legacy,
    /// 4 = Established; see `TcpHandshakeState::to_wire`).
    pub(crate) handshake_wire: u8,
    /// Admitted reverse-direction packets the serving pair has
    /// forwarded on this node for the tuple, when the serving table
    /// is readable (same worker). 0 cross-worker.
    pub(crate) rev_packets: u64,
    /// Node-wide reverse service observed for the tuple: any worker
    /// on this node forwarded reverse-direction packets for the
    /// canonical key. Carried separately from `rev_packets` (whose
    /// consumers mean "the readable serving pair was promoted AND
    /// served"); this is observed completion input only.
    pub(crate) rev_packets_any: u64,
    /// This node's workers observably completed the handshake for
    /// the tuple: both directions were forwarded somewhere node-wide
    /// (or a #16223 served cache-hit advanced it), so the pair is
    /// Established as an OUTPUT even if no single worker table holds
    /// an Established row. Input evidence only — never set from a
    /// shared row's Established wire.
    pub(crate) served_completed: bool,
    /// #18722: admitted packets (forward + reverse) the evidence
    /// sources have counted for the tuple, summed across sources:
    /// this table's serving rows, its node-served stamps and the
    /// shared synced row (restamped from the serving worker's live
    /// counters by the ct-slice). Every source is monotonic per
    /// incarnation, so the sum only moves when the serving pair
    /// forwards a packet. Read ONLY by the expiry pass's node-level
    /// retention arm, as a change-detection RECENCY proof
    /// (`SessionEntry::node_served_seen`): the other fields are
    /// cumulative, and keeping a row on cumulative proof kept a dead
    /// flow forever. Never a completion input.
    pub(crate) served_packets: u64,
    /// The Established wire came from the node's SHARED synced map:
    /// a serving worker published/restamped it only after its own
    /// pair completed the handshake. Trusted as completion proof on
    /// its own (installs publish Opening/Pending wires; the shared
    /// wire never reads Established for an unanswered SYN).
    pub(crate) shared_established: bool,
}

impl NodeServedEvidence {
    /// The serving pair on this node has promoted AND genuinely served
    /// the tuple, so a local replica/opening row may complete or be
    /// retained regardless of its own local flags. Locally-derived
    /// evidence additionally requires nonzero admitted reverse
    /// counters (folded only on admitted hits, never on dropped
    /// probes — a promoted-but-never-answered pair on ONE table
    /// cannot launder a half-open flow); shared-map evidence is
    /// trusted directly because the publisher completed the pair
    /// before the wire could read Established.
    #[inline]
    pub(crate) fn promoted_and_served(self) -> bool {
        self.shared_established
            || (self.handshake_wire == TcpHandshakeState::Established.to_wire()
                && self.rev_packets > 0)
    }

    /// OUTPUT-ONLY test for collectors (ct-slice restamp): this node
    /// knows the tuple completed — (a) any local row Established,
    /// (b) reverse service observed anywhere node-wide, or (c) a
    /// #16223 `cache_hit_handshake_progress` completion. Inputs are
    /// counters/completion observed anywhere node-local; a shared
    /// row's Established wire is deliberately NOT an input here
    /// (pass shared Established as OUTPUT only, via
    /// `promoted_and_served` where imports are the consumer).
    #[inline]
    pub(crate) fn served_and_completed(self) -> bool {
        self.promoted_and_served()
            || self.served_completed
            || self.rev_packets_any > 0
    }
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
