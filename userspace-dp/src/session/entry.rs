// Public-facing session data types extracted from session/mod.rs (#1047 P2 step 2).
// Pure relocation — bodies are byte-for-byte identical; visibility is
// unchanged (everything was already pub(crate)).
//
// SessionEntry (the internal storage type) stays in mod.rs because its
// fields are file-private and accessed directly by SessionTable's impl.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionDecision {
    pub(crate) resolution: ForwardingResolution,
    pub(crate) nat: NatDecision,
}

/// #919: zone names dropped from the fast path. `ingress_zone` and
/// `egress_zone` are now `u16` IDs that index into
/// `forwarding.zone_id_to_name` for slow-path consumers (logging,
/// gRPC export, status). `0` means "unknown / unset" (matches the
/// existing `UserspaceDpMeta.ingress_zone` default at afxdp/types/mod.rs:64).
/// Removing the `Arc<str>` saves 28 bytes per `SessionMetadata` and
/// eliminates the `LOCK XADD` atomic on every `metadata.clone()`.
/// #7096: the `{ingress_ifindex, ingress_vlan_id}` pair a session should be
/// STAMPED with, given whether its first packet arrived over the HA fabric.
///
/// For a fabric-redirected packet the two halves of the ingress record come from
/// different places and name different interfaces. The ZONE is overridden to the
/// peer-encoded ORIGINAL ingress zone (`stage_classify_fabric_ingress` →
/// `zone_pair_ids_for_flow_with_override`), which is correct: the flow logically
/// arrived on the peer's WAN. But `meta.ingress_ifindex` is whatever the XDP shim
/// stamped from `ctx->ingress_ifindex`, and NOTHING in production rewrites it —
/// verified by sweep: every `meta.ingress_ifindex = ...` assignment in the tree
/// is in a `#[cfg(test)]` fixture. So it is the LOCAL fabric member's netdev.
///
/// The peer's real ingress interface is NOT KNOWABLE here, and that is structural
/// rather than an omission: the fabric stamp carries a u16 zone id and nothing
/// else — two bytes big-endian in the synthetic fabric MAC
/// (`parse_zone_encoded_fabric_ingress_from_frame`, #3075). There is no interface
/// identity on the wire to recover.
///
/// So the honest stamp is NONE. Zero means "no ingress identity recorded" and the
/// Go consumers fall back to the #4792 zone approximation — which is exactly what
/// they already do for a peer-imported session, and what they do TODAY for this
/// case by accident. Naming the local fabric member instead would be a
/// confidently WRONG answer: `show security flow session interface ge-0-0-0`
/// would select flows that arrived on the peer's WAN, and `interface reth0.50`
/// would stop selecting them. Being a `clear` filter too, that is a wrong-session
/// deletion (#6975 / #6987 family).
///
/// Why this was latent rather than live, and why that is not a reason to leave
/// it: `buildSessionEgressIfaces` only keys an interface that has at least one
/// UNIT, and the shipped wiring gives the fabric member none — it appears only
/// inside `fab0 { fabric-options { member-interfaces { ge-0/0/0; } } }`. So the
/// lookup misses and the CLI falls back. The trigger is one config line
/// (`set interfaces ge-0/0/0 unit 0 ...`). The inertness rested on an operator
/// not writing it, and nothing in the tree bound that.
pub(crate) fn stamped_ingress_identity(
    ingress_ifindex: u32,
    ingress_vlan_id: u16,
    fabric_ingress: bool,
) -> (u32, u16) {
    if fabric_ingress {
        return (0, 0);
    }
    (ingress_ifindex, ingress_vlan_id)
}

#[derive(Clone, Debug)]
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: u16,
    pub(crate) egress_zone: u16,
    /// #4983: the ifindex of the binding this session's FIRST packet arrived
    /// on — the session's TRUE ingress-interface identity. Stamped ONCE at
    /// install from `UserspaceDpMeta::ingress_ifindex` (the binding the frame
    /// was actually received on) and never re-derived from `ingress_zone`
    /// afterwards; re-deriving is precisely the approximation this field
    /// exists to remove. For the sessions that are mirrored, `publish_conntrack`
    /// copies it into the conntrack map as `session_value.ingress_ifindex`,
    /// which is how the IN-DAEMON CLI's `show security flow session interface
    /// <name>` and the matching `clear` stop matching a session on interface X
    /// against a filter for a SIBLING interface Y of the same multi-interface
    /// zone (#4792 widened that CLI to consider every interface bound to the
    /// zone, which is as good as the approximation gets without this datum).
    /// The gRPC surface the REMOTE `cli` binary uses (`pkg/grpcapi`) and the
    /// REST surface (`pkg/api`) read the same identity since #6960; before
    /// that they answered an interface filter from the zone, so a remote
    /// `clear ... interface <name>` tore down sibling-interface sessions —
    /// see `session/README.md` "Which surfaces this applies to".
    ///
    /// SCOPE (#6965, CLOSED): `publish_bpf_conntrack_entry` is called from four
    /// sites in `afxdp/poll_descriptor` — the TRANSIT forward install, the
    /// host-inbound (LocalMiss) install, the missing-neighbor-seed install, and
    /// the reverse-companion repair. The transit site is #6965; before it,
    /// "for the sessions that are mirrored" excluded the dominant population
    /// outright — a transit session had no conntrack row at all, so this stamp,
    /// though correct on the in-memory entry, was not operator-visible for it.
    /// The gap predated #4983. What reaches the mirror is the {parent ifindex,
    /// VLAN} PAIR stamped below, resolved to a unit on the Go side.
    ///
    /// `0` means "no ingress identity carried" and is NEVER a valid ifindex.
    /// These populations legitimately carry `0`:
    ///   - the REVERSE companion — the reply's own ingress has not been
    ///     OBSERVED yet, and routing may be asymmetric, so there is nothing
    ///     truthful to stamp. (The CLI never interface-matches a reverse row
    ///     anyway: every show/clear call site skips `IsReverse != 0` first.)
    ///
    ///     An earlier revision gave the reason as "the forward flow's egress
    ///     interface is not resolved at install time". That is FALSE and was
    ///     retracted in the #6928 review: the decision installed alongside
    ///     this metadata already carries `resolution.egress_ifindex`, filled
    ///     in by the FIB / local-delivery / fabric resolvers. The forward
    ///     egress is available — it is simply the wrong datum, being a
    ///     PREDICTION of where the reply will arrive rather than an
    ///     OBSERVATION of where it did. Stamping it would put a confident
    ///     value on an unobserved binding, which is the failure mode `0`
    ///     exists to avoid.
    ///   - a PEER-SYNCED session — an ifindex is NODE-LOCAL, so the peer's
    ///     number names a different NIC here. Carrying it across the cluster
    ///     wire would produce a confidently WRONG interface name, strictly
    ///     worse than approximating, so it is deliberately not synced;
    ///   - the HOST-OUTBOUND GRE encapsulation path (`afxdp/tunnel.rs`) —
    ///     firewall-self-originated traffic read off the TUN device has no
    ///     ingress binding to record, so `0` is the correct answer there;
    ///   - the flow-cache descriptor seed, which is replay state for an
    ///     already-installed session and is never published as one.
    /// There is deliberately NO "pre-#4983 helper" population: `sessions` /
    /// `sessions_v6` are in the shim ABI pre-flight's checked set and a
    /// `ValueSize` mismatch against the live pin is a hard refusal
    /// (`validateUserspaceShimLivePins`), so a new daemon never reads an old
    /// helper's 136/184-byte rows. The targeted recovery is to unlink the ONE
    /// named pin (`docs/operations/userspace-shim-pin-recovery.md`), after
    /// which the next load recreates it at the new size.
    /// Whether a plain restart suffices is MODE-DEPENDENT, and this note
    /// asserted the wrong categorical until #6928. A bpffs pin does outlive the
    /// process that made it, so a HITLESS shutdown (`Manager.Close`, which
    /// preserves the pins on purpose) leaves the old-size pin in place and the
    /// pre-flight refuses again — but a NON-hitless HA shutdown calls
    /// `Manager.Teardown`, which `os.RemoveAll`s the pin path, so THERE a plain
    /// restart is already enough. "NOT a restart" was as wrong as the "a
    /// reload" it replaced. `xpfd cleanup` also clears it but is far broader
    /// (every pinned dataplane map, plus the FRR managed routes).
    /// The conclusion holds in every mode: either the pin is gone and the new
    /// map is empty, or the pre-flight refuses and the new daemon never reads
    /// the map. See `pkg/dataplane/types.go` for the canonical wording and
    /// `TestCleanupProductionCallersMatchRemediation_6928` for the binding.
    /// The MISSING-NEIGHBOR seed is NOT among them — it is a published forward
    /// session that outlives the neighbor resolution, so it is stamped from the
    /// frame's `meta` like the two other forward install sites. (Those two are
    /// not both "policy-admitted": the transit install is, but the LocalDelivery
    /// one also runs for a `JunosHostLocalPolicy::NoMatch` host-bound flow —
    /// admitted by the zone's host-inbound set with no junos-host policy
    /// matching at all. #6928 review.)
    /// The Go consumer falls back to the zone approximation for every zero
    /// (never "matches nothing", never "matches everything").
    ///
    /// FABRIC INGRESS is the one population where this field and
    /// `ingress_zone` name DIFFERENT interfaces, and the enumeration above is
    /// not exhaustive without it. A frame arriving over the fabric carries a
    /// zone-encoded override, so `ingress_zone` is the ORIGINATING chassis's
    /// zone (`poll_stages.rs` `parse_zone_encoded_fabric_ingress_from_frame`,
    /// given precedence over the ifindex->zone map in `forwarding/mod.rs`),
    /// while this stamp is unconditional and records the LOCAL fabric NIC the
    /// frame physically arrived on. Both are correct answers to different
    /// questions; they simply disagree.
    ///
    /// Operator consequence, if the fabric member is ever given a config
    /// unit: on node B, `show security flow session interface reth0.50` used
    /// to match a cross-chassis flow through the wan zone and would stop
    /// doing so, because the exact identity names the fabric NIC instead —
    /// and the matching `clear` would leave it behind.
    ///
    /// It is INERT today: the fabric member is declared only under
    /// `fab0 { fabric-options { member-interfaces { ... } } }` with no unit
    /// (`docs/ha-cluster-userspace.conf`), and `buildSessionEgressIfaces`
    /// keys on `{parent ifindex, unit VLAN}`, so a unit-less interface
    /// produces no map entry, the lookup misses, and the CLI falls back to
    /// the zone exactly as before. That is also why no test and no smoke
    /// would surface it — the path is unreachable from the shipped topology,
    /// not merely uncovered.
    pub(crate) ingress_ifindex: u32,
    /// #4983: the 802.1Q VLAN id this session's FIRST packet arrived with
    /// (`UserspaceDpMeta::ingress_vlan_id`). 0 means "no VLAN id recorded",
    /// which is USUALLY untagged but is not synonymous with it: a
    /// priority-tagged frame carries VID 0 with the tag present
    /// (`afxdp/frame/prop_tests/inspect.rs` covers exactly that shape), so a
    /// consumer must not infer "no tag" from a zero here (#6928 review). Stamped at install
    /// alongside `ingress_ifindex` and meaningful only with it: the PAIR is
    /// the logical ingress unit, and it is deliberately the same
    /// `{parent ifindex, vlan}` identity the Go side already resolves the
    /// EGRESS interface name by (`fib_ifindex`/`fib_vlan_id` →
    /// `buildSessionEgressIfaces`). Without the VLAN half, two units of one
    /// trunk NIC — e.g. `reth0.50` and `reth0.80` in the same zone — would
    /// alias onto the parent and reproduce the very cross-interface match
    /// this issue removes.
    pub(crate) ingress_vlan_id: u16,
    pub(crate) owner_rg_id: i32,
    pub(crate) fabric_ingress: bool,
    pub(crate) is_reverse: bool,
    /// For NAT64 sessions: stores original IPv6 addresses so reverse IPv4
    /// replies can be translated back.
    pub(crate) nat64_reverse: Option<Nat64ReverseInfo>,
    /// #2508: the admitting policy's per-policy RT_FLOW SYSLOG log
    /// selection (`then log session-init`/`session-close`). Stamped at
    /// install so the close-time delta (which no longer has the policy in
    /// hand) and the open-time delta can gate the per-policy RT_FLOW
    /// SYSLOG records. Independent of the global NetFlow/IPFIX close
    /// exporter (#2460), which observes every close regardless.
    pub(crate) log_session_init: bool,
    pub(crate) log_session_close: bool,
    /// #3056: the admitting policy's ID, in the same namespace Go assigns in
    /// `pkg/dataplane/userspace/policies.go` and pushes in the policy snapshot
    /// (mirrored back as `PolicyEvaluationResult.policy_id`). Stamped at install
    /// from the matched policy so the live-session BPF-compat publish
    /// (`show security flow session` rows) and the SESSION_CREATE RT_FLOW record
    /// reference the policy that admitted the flow instead of the `0` sentinel,
    /// which the Go side renders as the FIRST configured policy (policyID 0) — a
    /// wrong attribution. `0` remains the legitimate value for non-policy-
    /// forwarded sessions (firewall-local / neighbor-seed / fabric / tunnel).
    /// `SessionMetadata` carries no serde, so this rides the shared-session map
    /// and sibling-worker replicas automatically. #3301 also carries it across
    /// the cross-node HA session-sync wire (the SESSION_OPEN delta's trailing
    /// policy_id u32 + `SessionSyncRequest.policy_id`), so a peer-PROMOTED
    /// session resolves the admitting policy on its rows/close records after
    /// failover instead of `0`. An old peer omits the additive field
    /// (`serde(default)` 0), bit-identical to pre-#3301 (#1961 both-sides
    /// discipline; rolling-upgrade safe).
    pub(crate) policy_id: u32,
    /// #3227: the admitting application term's per-application inactivity (idle)
    /// timeout in NANOSECONDS, stamped at install from the matched policy's
    /// `PolicyEvaluationResult.inactivity_timeout` (seconds → ns). `None` means
    /// "use the global per-protocol `SessionTimeouts`" — the historical
    /// behavior, byte-identical for every flow whose application has no custom
    /// `inactivity-timeout`. When `Some`, `session_timeout_ns` uses it as the
    /// ESTABLISHED/idle expiry for the session, so the conntrack GC ages the
    /// session out on the app's value instead of the global timeout (closing the
    /// legacy-eBPF `appTimeout` parity regression). It does NOT override the
    /// short TCP closing/RST reap windows, matching Junos (inactivity-timeout is
    /// the idle timeout of an established session). Like `policy_id`, this rides
    /// the shared-session map and worker replicas; #3301 also carries it across
    /// the cross-node HA session-sync wire (the SESSION_OPEN delta + the
    /// `SessionSyncRequest.inactivity_timeout` SECONDS field, re-applied here via
    /// `app_inactivity_timeout_ns`), so a peer-promoted short-timeout session
    /// ages out on the app's value after failover without a real-traffic
    /// refresh. An old peer omits the field (0 → `None` → global timeout),
    /// rolling-upgrade safe.
    pub(crate) inactivity_timeout_ns: Option<u64>,
    /// #3073: a stable 1-based handle to the admitting policy rule's per-rule
    /// hit counter (`PolicyState::rules[idx-1].hit_counter`, resolved via
    /// `PolicyState::hit_counter_by_idx`). Stamped at install from the matched
    /// policy's `PolicyEvaluationResult.policy_counter_idx`. The established
    /// fast path (`poll_descriptor` session-hit and the flow-cache hit replay)
    /// uses it to increment the admitting policy's packet/byte counters on
    /// EVERY packet, so `show security policies hit-count` reflects the traffic
    /// the rule actually carries instead of only the first frame of each flow
    /// (the pre-#3073 cold-path-only count). `0` is reserved for "no counter":
    /// every non-policy-forwarded session (firewall-local / neighbor-seed /
    /// fabric / tunnel), which the fast path then leaves uncounted. The
    /// implicit default-policy is NOT `0`: #3363 stamps the reserved
    /// `DEFAULT_POLICY_COUNTER_IDX` (`u32::MAX`) sentinel, which
    /// `hit_counter_by_idx` resolves to `PolicyState::default_counter`, so a
    /// default-PERMIT session re-counts every packet on the fast path. The
    /// cold path still counts the first packet once
    /// in `try_match_rule`, so each packet is counted exactly once. Like
    /// `policy_id` (#3056), this rides the shared-session map and sibling-worker
    /// replicas; #3301 also carries it across the cross-node HA session-sync
    /// wire (the SESSION_OPEN delta + `SessionSyncRequest.policy_counter_idx`).
    /// HA requires identical config on both nodes, so the same idx resolves the
    /// same rule on the peer; a peer-promoted session therefore increments the
    /// correct policy counter on every forwarded packet after failover. An old
    /// peer omits the field (`serde(default)` 0 → no per-rule counter),
    /// rolling-upgrade safe.
    pub(crate) policy_counter_idx: u32,
    /// #3322: a reorder-stable, BOUND handle to the admitting rule's shared
    /// hit counter, resolved ONCE from `policy_counter_idx` at session install
    /// (`poll_descriptor` new-flow path) — when the index still points at the
    /// admitting rule — and carried for the life of the session. The
    /// established fast path prefers this Arc over re-resolving the positional
    /// `policy_counter_idx` against the CURRENT rule table
    /// (`PolicyState::resolve_session_hit_counter`), so a live policy
    /// insert/reorder that renumbers the rule table can no longer re-point an
    /// in-flight session's count at whatever rule now sits at the old index
    /// (#3322). The bound `Arc<PolicyRuleCounter>` is the same instance the
    /// persistent `PolicyCounterStore` keys by stable `rule_id`, so it stays
    /// valid across snapshot rebuilds (the store re-hands the same Arc for a
    /// surviving rule_id); when the admitting rule is DELETED the bound Arc is
    /// simply no longer read by `counter_snapshots` (its count goes nowhere),
    /// never a misattribution. `None` means "not bound" — the implicit
    /// default-policy / non-policy-forwarded sessions (idx 0), and peer-synced
    /// sessions materialized from the HA wire, which carry only the positional
    /// `policy_counter_idx` and fall back to idx resolution (pre-#3322
    /// behavior; HA requires identical config so the idx resolves the same
    /// rule at sync time). NOT serialized — `SessionMetadata` carries no serde
    /// and the binding is local, derived state re-resolved per node.
    pub(crate) policy_counter: Option<std::sync::Arc<crate::policy::PolicyRuleCounter>>,
}

// #3322: equality ignores `policy_counter`. It is a BOUND, derived handle to
// the admitting rule's shared counter (resolved from `policy_counter_idx`), not
// part of the session's wire/identity — two metadatas that agree on every wire
// field are equal whether or not the counter Arc has been resolved yet (e.g. a
// peer-synced entry before binding vs. a locally-installed one). Every other
// field participates, mirroring the previous `#[derive(PartialEq, Eq)]`.
impl PartialEq for SessionMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.ingress_zone == other.ingress_zone
            && self.egress_zone == other.egress_zone
            && self.ingress_ifindex == other.ingress_ifindex
            && self.ingress_vlan_id == other.ingress_vlan_id
            && self.owner_rg_id == other.owner_rg_id
            && self.fabric_ingress == other.fabric_ingress
            && self.is_reverse == other.is_reverse
            && self.nat64_reverse == other.nat64_reverse
            && self.log_session_init == other.log_session_init
            && self.log_session_close == other.log_session_close
            && self.policy_id == other.policy_id
            && self.inactivity_timeout_ns == other.inactivity_timeout_ns
            && self.policy_counter_idx == other.policy_counter_idx
    }
}

impl Eq for SessionMetadata {}

impl SessionMetadata {
    /// #5445: clone every field EXCEPT the bound `policy_counter` `Arc`, which
    /// is left `None`. Used by the per-packet established-session lookup return
    /// (`SessionLookup`, produced in `lookup_with_origin`) so the packet-
    /// forwarding hot path no longer bumps the SHARED `Arc<PolicyRuleCounter>`
    /// refcount — an atomic `LOCK XADD` on a cacheline every established-session
    /// lookup contends across workers, the #919 hot-path-atomic problem the
    /// plain `#[derive(Clone)]` reintroduced.
    ///
    /// The bound counter is still owned by the session-table `SessionEntry`
    /// (unchanged) and is re-sourced BY BORROW via
    /// `SessionTable::bound_policy_counter_for` for the per-packet policy
    /// hit-count and cloned at most once per flow into the flow-cache entry —
    /// so #3322 reorder-stable attribution is preserved with no per-packet
    /// atomic. Every other field is `Copy`, so this clone allocates nothing and
    /// touches no refcount. The explicit field list is deliberate: adding a new
    /// `SessionMetadata` field forces a compile error here (struct-literal
    /// exhaustiveness), so a future field cannot silently regress the hot path.
    #[inline]
    pub(crate) fn clone_without_policy_counter(&self) -> Self {
        Self {
            ingress_zone: self.ingress_zone,
            egress_zone: self.egress_zone,
            ingress_ifindex: self.ingress_ifindex,
            ingress_vlan_id: self.ingress_vlan_id,
            owner_rg_id: self.owner_rg_id,
            fabric_ingress: self.fabric_ingress,
            is_reverse: self.is_reverse,
            nat64_reverse: self.nat64_reverse,
            log_session_init: self.log_session_init,
            log_session_close: self.log_session_close,
            policy_id: self.policy_id,
            inactivity_timeout_ns: self.inactivity_timeout_ns,
            policy_counter_idx: self.policy_counter_idx,
            // #5445: the SHARED Arc is deliberately dropped from the per-packet
            // lookup return — see the method doc.
            policy_counter: None,
        }
    }
}

/// The per-packet result of an established-session lookup.
///
/// #5445: `metadata.policy_counter` is ALWAYS `None` on the value returned by
/// the primary/alias `SessionTable::lookup`(`_with_origin`) — the bound
/// `Arc<PolicyRuleCounter>` is intentionally NOT cloned onto the hot path (that
/// clone was a per-packet `LOCK XADD` on the shared refcount). Consumers that
/// need the bound counter borrow it from the owning `SessionEntry` via
/// `SessionTable::bound_policy_counter_for`. (Note: `ForwardSessionMatch`
/// returned by the once-per-flow `find_forward_*_match` finders still carries
/// the `Arc` — those feed reverse-companion install, an owner handoff, not the
/// per-packet fast path.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionLookup {
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForwardSessionMatch {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionOrigin {
    ForwardFlow,
    ReverseFlow,
    LocalMiss,
    MissingNeighborSeed,
    /// #7770: a PUNT SEED. This node is about to redirect a new flow across
    /// the fabric because the peer owns its egress RG, and it has adjudicated
    /// the flow against its OWN zone policy on the way past. The seed exists so
    /// the peer's RETURN — which arrives fabric-ingress in the reply direction,
    /// where policy can never permit it by design — is a session HIT instead of
    /// a `wan -> lan` default deny.
    ///
    /// Transient-local like `MissingNeighborSeed`: never HA-exported, never
    /// Open-delta'd. The AUTHORITATIVE session for the flow is the one the peer
    /// creates when it evaluates the punted packet; this is a local record of
    /// "I punted this and my own policy permitted it", and two nodes both
    /// claiming authority for one flow is what #518/#5007 exist to prevent.
    FabricPuntSeed,
    SyncImport,
    SharedMaterialize,
    SharedPromote,
    #[allow(dead_code)] // enum variant for completeness
    WorkerLocalImport,
}

impl SessionOrigin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ForwardFlow => "forward_flow",
            Self::ReverseFlow => "reverse_flow",
            Self::LocalMiss => "local_miss",
            Self::MissingNeighborSeed => "missing_neighbor_seed",
            Self::FabricPuntSeed => "fabric_punt_seed",
            Self::SyncImport => "sync_import",
            Self::SharedMaterialize => "shared_materialize",
            Self::SharedPromote => "shared_promote",
            Self::WorkerLocalImport => "worker_local_import",
        }
    }

    /// Returns true for origins that represent peer-synced sessions.
    /// These are sessions that arrived from the HA peer rather than
    /// being created by local traffic.
    pub(crate) fn is_peer_synced(self) -> bool {
        matches!(
            self,
            Self::SyncImport | Self::SharedMaterialize | Self::WorkerLocalImport
        )
    }

    pub(crate) fn is_promotable_synced(self) -> bool {
        matches!(self, Self::SyncImport | Self::SharedMaterialize)
    }

    pub(crate) fn worker_replica_origin(self) -> Self {
        if self.is_promotable_synced() {
            Self::SyncImport
        } else {
            Self::WorkerLocalImport
        }
    }

    pub(crate) fn materialized_shared_hit_origin(self) -> Self {
        if self.is_promotable_synced() {
            Self::SharedMaterialize
        } else {
            Self::WorkerLocalImport
        }
    }

    /// Transient LOCAL seeds: installed by this node's own cold path, never
    /// exported to the peer and never Open-delta'd (`install.rs`'s `counted`
    /// gate, `forward_export_candidates_for_owner_rgs`). #7770 adds
    /// `FabricPuntSeed` for the same reason `MissingNeighborSeed` is here: the
    /// entry is a local artefact of a decision this node made, not a claim of
    /// authority over the flow, and syncing it would put a NAT-free duplicate
    /// of the peer's authoritative session on the wire.
    pub(crate) fn is_transient_local_seed(self) -> bool {
        matches!(self, Self::MissingNeighborSeed | Self::FabricPuntSeed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionDeltaKind {
    Open,
    Close,
    /// #9412: a live session's TCP close class changed on the node that owns
    /// it. It carries the same record as an Open, plus `tcp_close_class`, so
    /// the peer re-upserts its copy with the close state.
    ///
    /// It is NOT an Open. The RT_FLOW SESSION_CREATE export and the close
    /// teardown both key on the exact kind, so neither fires for it.
    Update,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionDelta {
    pub(crate) kind: SessionDeltaKind,
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) fabric_redirect_sync: bool,
    /// #2465: monotonic (`CLOCK_MONOTONIC`) nanosecond timestamp at which the
    /// session was first installed, copied from the `SessionEntry.created_ns`.
    /// Carried so the RT_FLOW SESSION_CLOSE frame can report a real flow
    /// StartTime instead of the packet-count heuristic. `0` means "unknown"
    /// (e.g. an explicit delete path that no longer has the entry, or an
    /// HA-synced delta that never had a local install) — the exporter falls
    /// back to `estimateSessionDuration` in that case.
    pub(crate) created_ns: u64,
    /// #2465: monotonic nanosecond timestamp of the session's last activity
    /// (`SessionEntry.last_seen_ns`) at close time. Used together with
    /// `created_ns` to convert the monotonic creation instant to an absolute
    /// wall-clock StartTime at emit time without depending on a wall-clock
    /// reading taken inside the GC pass. `0` means "unknown".
    pub(crate) last_seen_ns: u64,
    /// #2501: the session's per-direction byte/packet counters at the moment
    /// this delta was produced. Snapshotted from `SessionEntry.counters` so
    /// the SESSION_CLOSE RT_FLOW frame (#2460) reports real NetFlow/IPFIX
    /// volume in its already-reserved wire slots. Meaningful only on a Close
    /// delta sourced from a live local entry; an Open delta and a
    /// synthesized close that no longer has the entry carry the
    /// `Default` (all-zero) value, which keeps the prior on-wire behavior.
    pub(crate) counters: SessionCounters,
    /// #2749: the IP ToS byte (DSCP in the high 6 bits, ECN cleared) observed
    /// on the forward direction of the session, snapshotted from
    /// `SessionEntry.observed_tos` when this delta is produced. Drives the
    /// re-introduced NetFlow v9 `srcTos` (IE 5) / IPFIX `ipClassOfService`
    /// close-record field. Meaningful only on a Close delta sourced from a
    /// live local entry; Open / synced / synthesized-close deltas carry 0
    /// (the prior on-wire behavior).
    pub(crate) observed_tos: u8,
    /// #2749: the OR of every TCP control-flag byte seen over the flow's
    /// lifetime (`SessionEntry.observed_tcp_flags`). Drives the re-introduced
    /// NetFlow v9 `tcpFlags` (IE 6) / IPFIX `tcpControlBits` close-record
    /// field. 0 for non-TCP flows and for deltas with no live entry in hand.
    pub(crate) observed_tcp_flags: u8,
    /// #4915: the dataplane's STABLE session id, copied from
    /// `SessionEntry.session_id`. Carried on BOTH the Open and Close delta so the
    /// RT_FLOW SESSION_CREATE / SESSION_CLOSE frames (#2508/#2460) can stamp the
    /// additive [152:160] wire slot with a value that (a) is identical across a
    /// session's create and close records and (b) disambiguates a reused 5-tuple
    /// — the per-event ordinal the Go side stamped before could do neither. `0`
    /// means "unknown" (a synthesized delta with no backing entry) and keeps the
    /// legacy "session id absent" rendering on the wire.
    pub(crate) session_id: u64,
    /// #8593: this delta is part of a BULK OWNER-RG EXPORT, not an incremental
    /// state change — the loss-of-sync resync re-announcing a live session so a
    /// peer can re-derive a complete snapshot.
    ///
    /// It exists so a DROP of this delta does not arm the loss-of-sync latch,
    /// because that latch triggers the very export that produced it. The export
    /// publishes through `flush_session_deltas` into the per-binding RPC-fallback
    /// buffer, which the export's own chunked drain does not empty and which the
    /// Go side polls on the ~5 s `DrainSessionDeltas` cadence — so the export
    /// overflows it, re-arms, and exports again. Measured on
    /// `loss:xpf-userspace-fw0`: 92% of 25.26M deltas dropped from 125,780 real
    /// session creates, still running ~149k deltas/s with zero traffic and zero
    /// active flows, ending only as the owned sessions aged out.
    ///
    /// Carried on the DELTA rather than passed at the flush call site
    /// deliberately. The call-site form was written first and is a worse shape:
    /// a new drain call site that passes the wrong flag SUPPRESSES a genuine
    /// arm, silently. Here the producer sets it, there is exactly one producer
    /// (`SessionTable::emit_open_delta_with_origin`, whose only production
    /// caller is the worker loop's chunked export), and a new call site cannot
    /// get it wrong because it does not choose.
    pub(crate) bulk_resync: bool,
    /// #9412: the session's TCP close class on the HA wire when this delta was
    /// produced. `0` means open or not carried; otherwise it is
    /// `TcpCloseClass::to_wire`.
    ///
    /// Open and Update deltas take it from the live entry. That lets the #2442
    /// loss-of-sync resync, which is an Open re-export, also restore a dropped
    /// Update. Close deltas carry `0`.
    pub(crate) tcp_close_class: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExpiredSession {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
}
