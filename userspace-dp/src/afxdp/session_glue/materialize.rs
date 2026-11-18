//! Shared-hit materialize-on-miss (#19153): a worker that misses its own table
//! and finds the flow in the shared map installs the shared row, under the
//! tuple gate's install protocol, from what shared authority holds at the
//! install. Split out of `resolve.rs` (the packet-path resolver), which calls
//! into it after the Owner verdict through
//! [`apply_deferred_shared_materialization`].

use super::*;

/// Test-only (#19153 fold 2): since fold 1 the poll path materializes through
/// [`apply_deferred_shared_materialization`]; these wrappers serve the cells
/// that drive one materialize of a capture directly.
#[cfg(test)]
pub(super) fn materialize_shared_session_hit(sessions: &mut SessionTable,
shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
resolved: &mut ResolvedSessionLookup,
forwarding: &ForwardingState,
now_ns: u64,
tcp_flags: u8,) -> (SessionLookup, bool) {
    materialize_shared_session_hit_adopted(
        sessions,
        shared_sessions,
        resolved,
        forwarding,
        now_ns,
        tcp_flags,
        false,
    )
}

/// #16217 (FZDiag30): adopted variant. `fabric_adopted` is true only
/// when the poll fabric-adoption gate has already proven this tuple
/// belongs to an Established session and this node is the RG owner
/// post-takeover. A synced replica materialized for such a flow may
/// replace a non-peer-synced local incumbent (`allow_replace_local`):
/// the incumbent is the stale pre-failover row (e.g. a
/// MissingNeighborSeed / locally seeded row) that the adoption
/// resolve supersedes, and refusing to clobber it left
/// `install_failed=true` on every adopted hit, so the flow-cache seed
/// gate (`flow_cache_seed.rs`) never installed an entry and every
/// packet re-took the slow path. Non-adopted materializations keep
/// `allow_replace_local=false` bit-identically (the #10582 clobber
/// guard).
///
/// #19153: the materialize joins the worker install protocol, as every other
/// worker install does ([`materialize_capture`]). Test-only, like its
/// non-adopted twin above. A refused permit, an absent
/// shared row, a shared row that no longer names the captured incarnation, or
/// a refused install returns `install_failed = true` and changes nothing.
/// What the poll path then does with the packet is
/// [`apply_deferred_shared_materialization`]'s decision.
///
/// Why: the commit-time policy-delete batch (`delete_policy_batch`) leases
/// the pair, deletes the worker rows, removes the shared rows and probes, all
/// under its lease. A materialize that took no permit could land after a
/// worker's delete, from the shared row the coordinator had not removed yet,
/// and restore the revoked incarnation for the rest of the flow's life.
#[cfg(test)]
pub(super) fn materialize_shared_session_hit_adopted(sessions: &mut SessionTable,
shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
resolved: &mut ResolvedSessionLookup,
forwarding: &ForwardingState,
now_ns: u64,
tcp_flags: u8,
fabric_adopted: bool,) -> (SessionLookup, bool) { if let Some(captured) = resolved.shared_entry.take() {
    return match materialize_capture(
        sessions,
        shared_sessions,
        forwarding,
        &captured,
        MaterializeInstall {
            now_ns,
            tcp_flags,
            fabric_adopted,
        },
    ) {
        CaptureMaterialize::Core(
            MaterializeOutcome::Installed(lookup) | MaterializeOutcome::SharedLocal(lookup),
            _,
        ) => (lookup, false),
        // The #10612 miss shape: nothing installed, nothing failed.
        CaptureMaterialize::CaptureFenced
        | CaptureMaterialize::Core(MaterializeOutcome::StaleReplayFenced, _) => {
            (resolved.lookup.clone(), false)
        }
        CaptureMaterialize::Refused
        | CaptureMaterialize::Core(
            MaterializeOutcome::SharedAbsent
            | MaterializeOutcome::Superseded
            | MaterializeOutcome::InstallRefused,
            _,
        ) => (resolved.lookup.clone(), true),
    };
}
(resolved.lookup.clone(), false) }

/// #19153: what one materialize of a resolve's capture did, before the caller
/// decides what that means for the packet.
#[derive(Clone, Debug)]
pub(in crate::afxdp::session_glue) enum CaptureMaterialize {
    /// The #10612 stale-replay fence refused the capture. Nothing claimed.
    CaptureFenced,
    /// Nothing claimed or installed: the pair is held (a coordinator lease, a
    /// sibling's permit, a publisher or a clear fence), or this worker's own
    /// local incumbent refuses a non-adopted install (#10582).
    Refused,
    /// The core ran under the permit: what it did, and how the current row it
    /// read compares with the capture (fold 2: judged before it installed).
    Core(MaterializeOutcome, MaterializeDivergence),
}

/// #19153: materialize a resolve's capture. Claims the pair, runs
/// [`materialize_current_shared_under_permit`] against the capture (its
/// identity, then the fold-2 classification), and drops the permit.
///
/// Two refusals cost no claim. A stale capture is fenced first (#10612). A
/// live local incumbent at the key (not a peer replica) refuses a non-adopted
/// install (`upsert_synced_with_origin`'s #10582 clobber guard), and this is
/// judged on this worker's own table, which only this worker mutates, so the
/// answer cannot change before the install. Judging it first keeps that
/// refusal, which lasts as long as the incumbent, off the gate entirely
/// (#19153 fold 1, r24 P3-1).
pub(in crate::afxdp::session_glue) fn materialize_capture(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    captured: &SyncedSessionEntry,
    install_inputs: MaterializeInstall,
) -> CaptureMaterialize {
    // #10612 (N2): fence stale-zone shared hits at materialize ingress.
    // A shared-transient stale row (import fail-open linger racing
    // validation) must materialize as a MISS, not install into the
    // worker table (the later arm-drop would not remove it). Fenced on the
    // capture before any permit, so a stale row costs no claim per packet;
    // the core fences the content it installs again.
    if synced_entry_is_stale_replay(captured.origin, &captured.metadata, forwarding) {
        note_stale_replay_fence_drop();
        return CaptureMaterialize::CaptureFenced;
    }
    if !install_inputs.fabric_adopted && sessions.holds_local_row(&captured.key) {
        return CaptureMaterialize::Refused;
    }
    // #19153: claim the pair before anything changes. A coordinator lease on
    // either tuple then refuses this install instead of letting it land
    // inside the lease. Never blocks. The non-allocating pre-check refuses the
    // common held case without building the permit set. `companion_key` is
    // the other half of the pair: the reply tuple for a forward row, the
    // forward tuple for a reverse row.
    let companion_key = reverse_session_key(&captured.key, captured.decision.nat);
    let gate = crate::afxdp::bpf_map::global_tuple_gate();
    if gate.install_claim_would_refuse(&[&captured.key, &companion_key]) {
        return CaptureMaterialize::Refused;
    }
    let Ok(install_permits) =
        gate.try_acquire_installs([captured.key.clone(), companion_key])
    else {
        return CaptureMaterialize::Refused;
    };
    let (outcome, divergence) = materialize_current_shared_under_permit(
        sessions,
        shared_sessions,
        forwarding,
        &captured.key,
        Some(CapturedIncarnation::of(captured)),
        Some(captured),
        install_inputs,
        &install_permits,
    );
    drop(install_permits);
    CaptureMaterialize::Core(outcome, divergence)
}

/// #19153 fold 2: what a materialize means for THIS packet, whose resolve,
/// Owner verdict and deferred effects (the promotion, the forwarding
/// revalidation) were all derived from the capture.
///
/// One rule, classify before apply: under the permit, the core compares the
/// current shared row with the capture BEFORE it installs anything
/// ([`materialize_divergence`]). Equal: the row is installed with this
/// packet's effects and every capture-derived effect stands. Different: the
/// current row is installed clean (none of this packet's state) and the
/// packet is dropped. No difference is exempt: the packet forwards on the
/// capture's decision only when the capture describes the installed row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) enum MaterializeDivergence {
    /// The current row equals the capture on everything this packet's
    /// handling read, or no capture was classified (a refusal or the #10612
    /// capture fence, whose packet handling is unchanged).
    #[default]
    None,
    /// The current row differs from the capture in a compared field, or the
    /// captured incarnation is gone (shared absent) or replaced (superseded:
    /// another NAT or session id). The core installed the current row, if at
    /// all, without this packet's TCP flags or fabric adoption; the deferred
    /// promotion and forwarding revalidation are dropped; the poll path
    /// recycles the frame, as the input-filter drop after the Owner verdict
    /// does. The next packet resolves current state.
    Drop,
}

/// #19153 fold 2: classify the CURRENT shared row against the resolve's
/// capture, before the core installs anything. `current` is the replica the
/// core is about to install, with its zero-to-live leak derivation already
/// applied. `live_leak` memoizes the leak incarnation forwarding names now
/// for the row's target (the core fills it when it derived one).
///
/// Every field of `SyncedSessionEntry` and of `SessionMetadata` is named (no
/// `..`), so a new field fails to compile until it is classified here.
///
/// Compared (any difference is `Drop`):
/// - the whole `SessionDecision` (resolution: disposition, egress, next hop;
///   the NAT decision; the install table domain and check);
/// - every `SessionMetadata` field: zones and their vintage, ingress
///   identity, NAT scope and NAT64 reverse, owner RG, fabric ingress,
///   direction and alias provenance, the admitting policy id, session
///   logging, the idle timeout, and the policy counter (`policy_counter_idx`
///   feeds the TUN-origin exemption, `policy_counter.is_some()` bypasses the
///   #10612 replay fence, so neither is accounting-only; the bound counter is
///   compared by identity);
/// - `source_nat_static` (SNAT provenance, which SNAT revalidation reads);
/// - the leak incarnation (#9951), as the incarnation each row RESOLVES
///   under: a nonzero stamp is itself; a zero stamp is unstamped and resolves
///   on current forwarding, exactly as a stamp equal to the live incarnation
///   does. So a zero capture equals a row the core stamped from current
///   forwarding (its zero-to-live derivation for peer-synced rows) or a
///   sibling stamped with the live incarnation, and differs from a revoked
///   stamp;
/// - for TCP, the close class and the handshake stage, decoded as
///   `upsert_synced_with_origin` decodes them (an unknown or legacy 0 stage
///   is Established, 0 close is open); other protocols install neither.
///
/// Not compared. Some of these ARE read elsewhere on the packet path; each
/// reason says why a difference cannot make this packet's capture-derived
/// effects wrong (#19153 fold 3 corrects fold 2's blanket "nothing reads
/// them"):
/// - `key`: the core re-read the row under the capture's key;
/// - `session_id`: the identity, judged first by
///   `promote::same_synced_incarnation` (with its legacy exception for a
///   current id of 0);
/// - `origin`: resolution and promotion read it, and TUN provenance has
///   forwarding meaning. Ordinary promotion and demotion rewrite it with the
///   content unchanged (`shared_ops/owner_rg.rs`); the install takes the
///   CURRENT origin (`Installed` or `SharedLocal`; a TUN row stays TUN), and a
///   promotion re-checks current shared ownership under its own permit. This
///   covers those transitions; it is not a claim that any origin change is
///   immaterial;
/// - `generation`: the HA install generation, bumped by every re-import of
///   the same incarnation. Its consumer, the deferred synced purge, is never
///   armed with a materialization (`keep_transient` picks one);
/// - `tcp_flags`: the publisher's last-seen flags. On `None` this packet's
///   flags replace them, except a FIN or RST, which the install never stamps
///   (#19175: the Owner replay applies it); on `Drop` they are the clean
///   install's own. The close class and handshake stage they imply are
///   compared, decoded;
/// - `fwd_packets`, `rev_packets`: service evidence the fabric-adoption gate
///   reads. A same-incarnation publish keeps their maxima
///   (`publish_shared_session`) and every restamp takes the max, so a normal
///   refresh only raises them and cannot withdraw evidence the capture had;
/// - `sibling_last_seen_ns`, `last_served_ns`: packet clocks for the expiry
///   and restore fences, also monotonic per incarnation at publish. Neither
///   supplies a route or a translation to this packet;
/// - `pptp_call_ids`: re-export data, absent from `into_session_install`;
/// - `persistent_lease_hold`: read by the install, which fails if it cannot
///   join it. The core joins the CURRENT row's exact hold after this
///   classification and never replays the captured one.
pub(in crate::afxdp) fn materialize_divergence(
    forwarding: &ForwardingState,
    captured: &SyncedSessionEntry,
    current: &SyncedSessionEntry,
    live_leak: &mut Option<u64>,
) -> MaterializeDivergence {
    let SyncedSessionEntry {
        key: _,
        decision,
        metadata,
        source_nat_static,
        leak_incarnation,
        origin: _,
        protocol,
        tcp_flags: _,
        generation: _,
        session_id: _,
        tcp_close_class,
        tcp_handshake_state,
        rev_packets: _,
        fwd_packets: _,
        sibling_last_seen_ns: _,
        last_served_ns: _,
        pptp_call_ids: _,
        persistent_lease_hold: _,
    } = current;
    let SessionMetadata {
        ingress_zone,
        egress_zone,
        ingress_zone_check,
        egress_zone_check,
        ingress_ifindex,
        ingress_vlan_id,
        forward_ingress_vlan_id,
        nat_scope_ifindex,
        owner_rg_id,
        fabric_ingress,
        is_reverse,
        forward_wire_alias_origin,
        nat64_reverse,
        log_session_init,
        log_session_close,
        policy_id,
        inactivity_timeout_ns,
        policy_counter_idx,
        policy_counter,
    } = metadata;
    let was = &captured.metadata;
    let differs = *decision != captured.decision
        || *ingress_zone != was.ingress_zone
        || *egress_zone != was.egress_zone
        || *ingress_zone_check != was.ingress_zone_check
        || *egress_zone_check != was.egress_zone_check
        || *ingress_ifindex != was.ingress_ifindex
        || *ingress_vlan_id != was.ingress_vlan_id
        || *forward_ingress_vlan_id != was.forward_ingress_vlan_id
        || *nat_scope_ifindex != was.nat_scope_ifindex
        || *owner_rg_id != was.owner_rg_id
        || *fabric_ingress != was.fabric_ingress
        || *is_reverse != was.is_reverse
        || *forward_wire_alias_origin != was.forward_wire_alias_origin
        || *nat64_reverse != was.nat64_reverse
        || *log_session_init != was.log_session_init
        || *log_session_close != was.log_session_close
        || *policy_id != was.policy_id
        || *inactivity_timeout_ns != was.inactivity_timeout_ns
        || *policy_counter_idx != was.policy_counter_idx
        || match (policy_counter, &was.policy_counter) {
            (Some(left), Some(right)) => !Arc::ptr_eq(left, right),
            (None, None) => false,
            _ => true,
        }
        || *source_nat_static != captured.source_nat_static
        || (*protocol == PROTO_TCP
            && (crate::session::TcpCloseClass::from_wire(*tcp_close_class)
                != crate::session::TcpCloseClass::from_wire(captured.tcp_close_class)
                || installed_handshake_stage(*tcp_handshake_state)
                    != installed_handshake_stage(captured.tcp_handshake_state)))
        || (*leak_incarnation != captured.leak_incarnation && {
            let live = *live_leak.get_or_insert_with(|| live_leak_incarnation(forwarding, current));
            resolves_under(*leak_incarnation, live) != resolves_under(captured.leak_incarnation, live)
        });
    if differs {
        MaterializeDivergence::Drop
    } else {
        MaterializeDivergence::None
    }
}

/// The handshake stage `upsert_synced_with_origin` installs for a TCP wire
/// byte: an unknown or legacy 0 byte installs as Established.
fn installed_handshake_stage(wire: u8) -> crate::session::TcpHandshakeState {
    crate::session::TcpHandshakeState::from_wire(wire)
        .unwrap_or(crate::session::TcpHandshakeState::Established)
}

/// #9951: the incarnation a row with leak stamp `stamp` resolves under. A
/// zero stamp carries no provenance and resolves on current forwarding, which
/// is the live incarnation `live` (0 when the target rides no leak).
fn resolves_under(stamp: u64, live: u64) -> u64 {
    if stamp == 0 { live } else { stamp }
}

/// #9951: the leak incarnation forwarding names NOW for `entry`'s resolution
/// target, or 0 when its resolution rides no leak.
fn live_leak_incarnation(forwarding: &ForwardingState, entry: &SyncedSessionEntry) -> u64 {
    let target = if entry.metadata.is_reverse {
        entry.key.dst_ip
    } else {
        let flow = SessionFlow {
            src_ip: entry.key.src_ip,
            dst_ip: entry.key.dst_ip,
            forward_key: entry.key.clone(),
        };
        resolution_target_for_session(&flow, entry.decision)
    };
    leak_incarnation_for_session(forwarding, entry.decision, target).unwrap_or(0)
}

/// #19153 fold 1: drops of packets whose materialize found the captured
/// incarnation gone, replaced, or a current row that differs from the
/// capture ([`MaterializeDivergence::Drop`]). No log. Fold 2 (r24 P3):
/// exported as `ProcessStatus.materialize_divergence_drops` and the
/// Prometheus counter `xpf_userspace_materialize_divergence_drops_total`, so
/// a gate can measure what a takeover drops here. Read it as a delta across
/// the takeover, not as an invariant zero: a sibling's shared write that lands
/// inside one packet's capture-to-claim window still drops that one packet.
pub(in crate::afxdp) static MATERIALIZE_DIVERGENCE_DROPS: AtomicU64 = AtomicU64::new(0);

/// Bump [`MATERIALIZE_DIVERGENCE_DROPS`] for one recycled packet.
pub(in crate::afxdp) fn note_materialize_divergence_drop() {
    MATERIALIZE_DIVERGENCE_DROPS.fetch_add(1, Ordering::Relaxed);
}

/// The status surface's read of [`MATERIALIZE_DIVERGENCE_DROPS`]
/// (`Coordinator::materialize_divergence_drops`).
pub(in crate::afxdp) fn materialize_divergence_drops() -> u64 {
    MATERIALIZE_DIVERGENCE_DROPS.load(Ordering::Relaxed)
}

/// #19153: the identity a resolve captured from a shared row, the incarnation
/// a materialize expects shared authority to still name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct CapturedIncarnation {
    pub(in crate::afxdp) nat: NatDecision,
    pub(in crate::afxdp) session_id: u64,
}

impl CapturedIncarnation {
    pub(in crate::afxdp) fn of(entry: &SyncedSessionEntry) -> Self {
        Self {
            nat: entry.decision.nat,
            session_id: entry.session_id,
        }
    }
}

/// #19153: the per-packet install inputs of a materialize. Fold 2: both are
/// this packet's state, applied only to a row the classification found equal
/// to the capture.
#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct MaterializeInstall {
    pub(in crate::afxdp) now_ns: u64,
    /// The packet's TCP flags, stamped on an installed row equal to the
    /// capture (its timeout derives from them). A row that differs keeps its
    /// own carried flags. #19175: a TCP FIN or RST is never stamped here
    /// ([`close_owed_to_owner_replay`]): the row takes its carried flags and
    /// close class, and the poll path applies the packet's close through the
    /// #13938 Owner replay.
    pub(in crate::afxdp) tcp_flags: u8,
    /// #16217: the replica may replace a non-peer-synced local incumbent. The
    /// adoption gate judged this packet against the shared state it read, so
    /// a row that differs from the capture never gets it.
    pub(in crate::afxdp) fabric_adopted: bool,
}

/// #19175: whether a packet's TCP close (FIN or RST) must be left out of the
/// materialize install and applied by the #13938 Owner replay instead.
///
/// Why: an install that stamps the close (`upsert_synced_with_origin` derives
/// `closing`, `reset` and `fin_own` from the install's flags) does it outside
/// the local-hit state machine. None of the steps that carry a close to the
/// rest of the flow run there: the companion propagation (#4109 F17), the HA
/// Update (#9412), the cross-worker close relay (#18520) and the #16489
/// closing-counter baseline all hang off `stamp_tcp_close` reporting progress
/// in the lookup (`session/lookup.rs`). And once the install has stamped it,
/// a replay of the same packet sees no progress. So the install takes the
/// shared row's carried close state, as promotion strips the close from its
/// flip (`promote_synced_with_origin`), and the poll site replays the packet
/// on the installed row after the promotion, exactly as for a local hit.
///
/// Keyed on the session key's protocol, which is what the replay's lookup
/// keys its close on (`is_tcp`).
#[inline]
pub(in crate::afxdp) fn close_owed_to_owner_replay(protocol: u8, tcp_flags: u8) -> bool {
    protocol == PROTO_TCP && crate::tcp_flags::is_closing(tcp_flags)
}

/// #19153: what [`materialize_current_shared_under_permit`] did. Only
/// `Installed` and `SharedLocal` changed anything.
#[derive(Clone, Debug)]
pub(in crate::afxdp) enum MaterializeOutcome {
    /// Installed the CURRENT shared row as a peer-synced replica
    /// (`SharedMaterialize`). Carries the installed row's lookup.
    Installed(SessionLookup),
    /// Installed the CURRENT shared row, which shared authority records as
    /// locally owned (not peer-synced: a sibling's `SharedPromote`, or a
    /// worker's own publish), as a `WorkerLocalImport` (or TUN-origin)
    /// replica. Materialize-on-miss has always installed these. A promotion
    /// caller must not promote it: the owner is already local.
    SharedLocal(SessionLookup),
    /// No shared row under the key: a completed delete (a peer delete, the
    /// commit-time policy batch) removed it. Nothing installed.
    SharedAbsent,
    /// The shared row names a different incarnation than the caller's
    /// capture (`promote::same_synced_incarnation`). Only reported when the
    /// caller supplied a capture. Nothing installed.
    Superseded,
    /// The #10612 stale-replay fence refused the current row (its zones
    /// vanished). Nothing installed.
    StaleReplayFenced,
    /// The install itself was refused, nothing installed:
    /// - the caller's permits do not fence the current row's companion tuple
    ///   (its translation changed since the caller claimed the pair);
    /// - the publisher's persistent lease hold could not be joined;
    /// - `upsert_synced_with_origin` refused to replace a local incumbent
    ///   (the #10582 clobber guard).
    InstallRefused,
}

/// #19153: install the CURRENT shared row for `key` into this worker's table,
/// for a caller that ALREADY holds the worker install permits on the pair.
/// `permits` is the witness, as for
/// `bpf_map::update_session_cluster_synced_origin_under_permit`: debug builds
/// assert that one of them fences `key`, and the install is refused unless one
/// fences the current row's companion tuple too. Under those permits no lease
/// of the pair (an HA import or delete, the commit-time policy-delete batch, a
/// pressure shed) can run, so the shared row re-read here stays authoritative
/// until the install.
///
/// The row installed is what shared authority holds NOW, never a caller's
/// earlier copy. `expected` (the identity of a resolve's capture) first
/// decides whether the caller's packet resolved against this incarnation
/// (`promote::same_synced_incarnation`, the one identity rule); a mismatch is
/// `Superseded` and installs nothing. This is also how the zero-id case is
/// handled: a shared id of 0 matches on the NAT decision alone, and even then
/// the capture is never taken as the row's state. The current row's content is
/// installed, so a legacy peer's same-NAT reuse of the tuple cannot install
/// the stale capture.
///
/// #19153 fold 2, classify before apply: with a full capture
/// (`classify_against`, whose identity must be `expected`) the current row is
/// compared with it ([`materialize_divergence`]) after the re-read and BEFORE
/// any install. The returned divergence is what the packet may do:
/// - `None`: the row is installed with this packet's TCP flags and fabric
///   adoption, exactly as before, except a TCP FIN or RST (#19175,
///   [`close_owed_to_owner_replay`]): the row then keeps its carried flags
///   and close class, and the caller owes the packet's close to the Owner
///   replay;
/// - `Drop`: the row is installed clean, with its own carried flags and no
///   adoption (it may then be refused by a local incumbent), and the caller
///   drops the packet. An absent or superseded capture is `Drop` too, with
///   nothing installed.
///
/// An identity-only caller (`classify_against` `None`) gets `None` and the
/// packet's effects, as before fold 2.
///
/// Order: every check, the leak derivation and the classification run before
/// the first side effect (joining the publisher's persistent lease hold), so
/// every outcome but `Installed` and `SharedLocal` changes nothing. Lock order
/// is the permits, then the shared lock, as in promotion and the HA import (a
/// lease, then the shared lock). The shared lock is released before the
/// install, and a permit is never waited for, so no cycle exists.
///
/// Cost: runs once per materialize attempt, which is once per flow per worker
/// unless the attempt is refused. A refused attempt is retried by the flow's
/// next packet for as long as its cause lasts. Through `materialize_capture`,
/// a held pair costs the non-allocating claim pre-check (lock operations) and
/// a worker-local #10582 incumbent costs one table probe, both without
/// claiming. A refusal inside this core (a persistent hold that cannot be
/// joined, a directory conflict, a companion the claim does not cover) pays
/// the claim (allocations), the shared re-read and the release on each
/// attempt. The classification is field compares, plus at most one leak
/// lookup, shared with the zero-to-live derivation. No logging.
#[expect(clippy::too_many_arguments, reason = "#19153 fold 2: the core's permit witness, identity, capture and install inputs; one caller per mode")]
pub(in crate::afxdp) fn materialize_current_shared_under_permit(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    expected: Option<CapturedIncarnation>,
    classify_against: Option<&SyncedSessionEntry>,
    install_inputs: MaterializeInstall,
    permits: &[crate::afxdp::bpf_map::InstallPermit],
) -> (MaterializeOutcome, MaterializeDivergence) {
    debug_assert!(
        permits.iter().any(|permit| permit.covers(key)),
        "#19153: materialize under permits that do not fence {key:?}"
    );
    debug_assert!(
        classify_against.is_none() || expected == classify_against.map(CapturedIncarnation::of),
        "#19153: a classified capture must be the expected incarnation"
    );
    let MaterializeInstall {
        now_ns,
        tcp_flags,
        fabric_adopted,
    } = install_inputs;
    // A capture whose incarnation is gone or replaced: the packet resolved
    // against state shared authority no longer names.
    let gone = if classify_against.is_some() {
        MaterializeDivergence::Drop
    } else {
        MaterializeDivergence::None
    };
    // Re-read under the permits, and copy out only an incarnation the caller
    // may install. One clone, inside the lock.
    let (mut replica, shared_origin) = {
        let shared = lock_shared_recover(shared_sessions);
        let Some(current) = shared.get(key) else {
            return (MaterializeOutcome::SharedAbsent, gone);
        };
        if let Some(expected) = expected
            && !super::promote::same_synced_incarnation(
                expected.nat,
                expected.session_id,
                current,
            )
        {
            return (MaterializeOutcome::Superseded, gone);
        }
        (synced_replica_entry(current), current.origin)
    };
    // A zero token carries no leak provenance and is recomputed locally
    // for peer-synced rows. A nonzero token was computed before this
    // shared row was published (and survives demotion), so preserve it as
    // revocation evidence. Read-only; the classification below reuses the
    // live incarnation it computed.
    let mut live_leak = None;
    if shared_origin.is_peer_synced() && replica.leak_incarnation == 0 {
        let live = live_leak_incarnation(forwarding, &replica);
        live_leak = Some(live);
        replica.leak_incarnation = live;
    }
    // #19153 fold 2: classify BEFORE anything is applied.
    let divergence = match classify_against {
        Some(captured) => materialize_divergence(forwarding, captured, &replica, &mut live_leak),
        None => MaterializeDivergence::None,
    };
    let companion_key = reverse_session_key(&replica.key, replica.decision.nat);
    if !permits.iter().any(|permit| permit.covers(&companion_key)) {
        return (MaterializeOutcome::InstallRefused, divergence);
    }
    // #10612 (N2): the fence judges the content installed.
    if synced_entry_is_stale_replay(shared_origin, &replica.metadata, forwarding) {
        note_stale_replay_fence_drop();
        return (MaterializeOutcome::StaleReplayFenced, divergence);
    }
    // What the install may take from this packet: everything when the row
    // equals the capture, nothing when it differs (Codex P2-1: an RST or FIN
    // that is dropped must not have closed or reset the row first). #19175:
    // never the packet's FIN or RST. The row keeps its carried flags and close
    // class, and the caller replays the close through the Owner replay, where
    // the companion, the HA Update, the close relay and the closing-counter
    // baseline see it.
    let (packet_tcp_flags, allow_replace_local) = match divergence {
        MaterializeDivergence::None => (
            (!close_owed_to_owner_replay(key.protocol, tcp_flags)).then_some(tcp_flags),
            fabric_adopted,
        ),
        MaterializeDivergence::Drop => (None, false),
    };
    let incumbent_persistent_hold = sessions.persistent_lease_hold_for(&replica.key);
    // The first side effect. A shared row's hold belongs to its publisher,
    // not this worker. Acquire one local reference on that exact allocator
    // and lease incarnation before installing a releasable local hold. The
    // destination tuple check prevents a stale row from joining a different
    // lease under the same key.
    let acquired_persistent_hold = if let Some(hold) = replica.persistent_lease_hold {
        let expected_translated = crate::nat::TranslatedTuple {
            ip: replica.key.dst_ip,
            port: replica.key.dst_port,
        };
        if !crate::nat::acquire_recorded_persistent_inbound_hold(
            &forwarding.source_nat_rules,
            hold,
            expected_translated,
            now_ns,
        ) {
            return (MaterializeOutcome::InstallRefused, divergence);
        }
        Some(hold.with_owner(crate::nat::PersistentLeaseOwner::LocalWorker))
    } else {
        None
    };
    // #17058: build the install via the one shared mapping
    // (`into_session_install`), then apply the materialize overrides:
    // the shared-hit origin, this packet's tcp_flags when the row equals the
    // capture (unless they carry a close, #19175), and the locally acquired
    // persistent hold (the shared row's
    // hold belongs to its publisher). Every other field (id, close/handshake
    // state, counters, SNAT provenance, and a differing row's tcp_flags) is
    // the replica's carried value.
    // Snapshot the post-install reads first: `into_session_install`
    // consumes the replica, and the lookup/stamp below still need them.
    let replica_key = replica.key.clone();
    let replica_decision = replica.decision;
    let replica_metadata = replica.metadata.clone();
    let replica_session_id = replica.session_id;
    let replica_source_nat_static = replica.source_nat_static;
    let replica_leak_incarnation = replica.leak_incarnation;
    let mut install = replica.into_session_install(now_ns);
    install.origin = shared_origin.materialized_shared_hit_origin();
    if let Some(packet_tcp_flags) = packet_tcp_flags {
        install.tcp_flags = packet_tcp_flags;
    }
    install.persistent_lease_hold = acquired_persistent_hold;
    // #19175 fold 1 (Codex P2-2): a close this worker already applied to the
    // SAME incarnation it is about to replace (the fabric wire placeholder
    // arm re-materializes its replica on every packet; an adopted install
    // may replace a local row) survives the re-install. The install
    // reconstructs close state from the shared class alone, which carries no
    // FIN direction for CLOSING, so a retransmitted FIN would otherwise read
    // as fresh progress and F17 would move the companion's close deadline.
    let carried_close =
        sessions.same_incarnation_close_progress(&replica_key, replica_session_id, replica_decision.nat);
    let materialized = sessions.upsert_synced_with_origin(
        install,
        allow_replace_local,
    );
    if materialized && let Some(carried_close) = carried_close {
        sessions.carry_close_progress(&replica_key, carried_close, now_ns);
    }
    if materialized {
        // The install replaced and discarded the incumbent table entry. Its
        // exact local reference is no longer owned, even when the new entry
        // selected the same lease (the pre-install acquire made a second one).
        if let Some(hold) = incumbent_persistent_hold {
            crate::nat::release_recorded_persistent_inbound_hold(
                &forwarding.source_nat_rules,
                hold,
                now_ns,
            );
        }
    } else if let Some(hold) = acquired_persistent_hold {
        // A refused materialization did not adopt the local reference.
        crate::nat::release_recorded_persistent_inbound_hold(
            &forwarding.source_nat_rules,
            hold,
            now_ns,
        );
    }
    if !materialized {
        // A refused shared repair must not mutate the incumbent local row's
        // leak provenance; failed clobber attempts return InstallRefused.
        return (MaterializeOutcome::InstallRefused, divergence);
    }
    // The stamp is evidence for the materialized replica only.
    if replica_leak_incarnation != 0 {
        sessions.stamp_leak_incarnation(&replica_key, replica_leak_incarnation);
    }
    let lookup = SessionLookup {
        decision: replica_decision,
        metadata: replica_metadata,
        forwarding_generation: ForwardingGenerationStamp::default(),
        aux: SessionLookupAux {
            session_id: replica_session_id,
            source_nat_static: replica_source_nat_static,
            leak_incarnation: replica_leak_incarnation,
        },
    };
    let outcome = if shared_origin.is_peer_synced() {
        MaterializeOutcome::Installed(lookup)
    } else {
        MaterializeOutcome::SharedLocal(lookup)
    };
    (outcome, divergence)
}

/// Materialize a shared entry only after the packet's Owner verdict.
///
/// #19153 folds 1 and 2: the resolve captured the shared row, and this
/// packet's Owner verdict, its deferred promotion and its deferred forwarding
/// revalidation were all derived from that capture. The materialize installs
/// what shared holds NOW, and classifies it against the capture before it
/// installs (`materialize_current_shared_under_permit`). The classification
/// decides what the packet may still do (`resolved.materialize_divergence`):
///
/// - `MaterializeDivergence::None` (the current row equals the capture on
///   every compared field): the row was installed with this packet's effects,
///   and every capture-derived effect describes it and stands;
/// - `Drop` (any compared field differs, or the captured incarnation is absent
///   or superseded in shared): the current row was installed without this
///   packet's effects (or nothing was, for absent or superseded); the
///   promotion and the revalidation are dropped, so neither writes the
///   capture's content over the installed row; and the poll site recycles the
///   packet instead of forwarding it on a decision shared no longer names.
///
/// The next packet resolves the installed row as a worker hit, or current
/// shared state, and promotes normally. One exception (fold 3, Codex re-check
/// P2): a row that is a fabric wire placeholder sends every translated packet
/// back to the shared wire alias (`shared_ops/lookup.rs`). When the alias slot
/// is its canonical row's republication, that capture is the CURRENT canonical
/// row (`lookup_shared_forward_wire_capture`), not the alias's own lagging
/// copy, so it equals the re-read unless a canonical write lands in that
/// packet's own capture-to-claim window. Each such write can drop at most one
/// packet per worker, and lag between the alias and its canonical row,
/// however long, drops nothing. When the predicate fails (the canonical row is
/// absent, reverse, or under another translation) the capture IS the alias's
/// copy and drops as `SharedAbsent`/`Superseded`; that is outside the bound,
/// and an obsolete alias from a translation-changing replacement is never
/// removed (#19179), so its packets drop every time.
///
/// Every `deferred_*` effect of `ResolvedFlowSessionDecision`, on `Drop`:
/// - `deferred_synced_promotion`: DROPPED. It carries the capture's decision
///   and metadata, which the flip would write over the installed row and then
///   publish as `SharedPromote`;
/// - `deferred_forwarding_revalidation`: DROPPED. Its resolution, owner RG and
///   egress zone were derived from the capture's decision and metadata, and
///   `apply_deferred_forwarding_revalidation` writes them into the row under
///   `resolved.key`, which is now the installed row;
/// - `deferred_shared_materialization`: consumed here;
/// - `deferred_synced_purge`: never set with a materialization (the resolve
///   arms one or the other on `keep_transient`), so there is nothing to drop;
/// - the #13938 owner-hit replay (`authority_deferred`): false for a shared
///   hit (`ResolvedSessionLookup::shared`) and left false, so nothing is
///   replayed. The poll site recycles the frame before its replay arm anyway.
///
/// #19175, the packet's TCP close: a FIN or RST whose materialize INSTALLED a
/// row equal to the capture (`Installed` or `SharedLocal`, divergence `None`)
/// left the close out of the install ([`close_owed_to_owner_replay`]). This
/// sets `resolved.authority_deferred`, so the poll site's #13938 Owner replay
/// (`apply_deferred_owner_hit_with_ack` on `resolved.key`, the installed key)
/// applies it as it does for a local hit: after the deferred promotion and the
/// forwarding revalidation, through `stamp_tcp_close`, so the companion (F17),
/// the HA Update, the close relay and the closing-counter baseline run from
/// that one place. Every disposition replays, `FabricRedirect` included, as a
/// local hit does. Nothing else owes it: a non-closing packet's flags are
/// still installed as before; a refusal, a fence or a `Drop` installed this
/// packet's nothing and replays nothing.
///
/// Refusals keep their pre-fold handling: a held pair, a #10582 local
/// incumbent, or a refused install of a row equal to the capture forwards on
/// the capture (`install_failed`, seed suppressed, promotion dropped), and the
/// #10612 fence of an unchanged row keeps its miss shape.
pub(in crate::afxdp::session_glue) fn apply_deferred_shared_materialization(
    sessions: &mut SessionTable,
    // #19153: the shared map the resolve captured the entry from, re-read
    // under the install permit before the install.
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    now_ns: u64,
    tcp_flags: u8,
    verdict: SessionHitVerdict,
    resolved: &mut ResolvedFlowSessionDecision,
) {
    if verdict != SessionHitVerdict::Owner {
        return;
    }
    let Some(captured) = resolved
        .deferred_shared_materialization
        .take()
        .map(|deferred| deferred.entry)
    else {
        return;
    };
    #[cfg(test)]
    run_materialize_before_claim_hook();
    // `installed`: the core installed a row (only `Installed` and
    // `SharedLocal` change anything).
    let (install_failed, divergence, installed) = match materialize_capture(
        sessions,
        shared_sessions,
        forwarding,
        &captured,
        MaterializeInstall {
            now_ns,
            tcp_flags,
            fabric_adopted: resolved.fabric_adopted,
        },
    ) {
        // The #10612 miss shape: nothing installed, nothing failed.
        CaptureMaterialize::CaptureFenced => (false, MaterializeDivergence::None, false),
        CaptureMaterialize::Refused => (true, MaterializeDivergence::None, false),
        CaptureMaterialize::Core(outcome, divergence) => match outcome {
            MaterializeOutcome::Installed(installed)
            | MaterializeOutcome::SharedLocal(installed) => {
                // What was installed is what was classified: a row judged
                // equal carries the capture's decision.
                debug_assert!(
                    divergence != MaterializeDivergence::None
                        || installed.decision == captured.decision,
                    "#19153: an installed row classified equal differs from the capture"
                );
                (false, divergence, true)
            }
            MaterializeOutcome::StaleReplayFenced => (false, divergence, false),
            MaterializeOutcome::SharedAbsent
            | MaterializeOutcome::Superseded
            | MaterializeOutcome::InstallRefused => (true, divergence, false),
        },
    };
    resolved.install_failed = install_failed;
    resolved.materialize_divergence = divergence;
    // #19175: the install left this packet's FIN or RST out (the core's
    // `close_owed_to_owner_replay` rule); the poll site's Owner replay applies
    // it on the installed row. The replay targets `resolved.key`, which for a
    // shared hit IS the captured key (`ResolvedSessionLookup::shared` resolves
    // to `Canonical(entry.key)`); on any other key it would mutate a row this
    // packet did not install, so the close is withheld rather than misapplied.
    if installed
        && divergence == MaterializeDivergence::None
        && close_owed_to_owner_replay(captured.key.protocol, tcp_flags)
    {
        debug_assert_eq!(
            resolved.key, captured.key,
            "#19175: a materialized close is replayed on a key the materialize did not install"
        );
        if resolved.key == captured.key {
            resolved.authority_deferred = true;
        }
    }
    if resolved.session_id == 0 && !install_failed {
        resolved.session_id = sessions.session_id_for(&resolved.key);
    }
    if install_failed || divergence != MaterializeDivergence::None {
        resolved.deferred_synced_promotion = None;
    }
    if divergence != MaterializeDivergence::None {
        resolved.deferred_forwarding_revalidation = None;
    }
}

#[cfg(test)]
std::thread_local! {
    static MATERIALIZE_BEFORE_CLAIM_HOOK_19153: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

/// #19153 fold 1 test seam: run `hook` once, on this thread, between the
/// resolve's capture and the materialize's claim (a shared replacement that
/// completes in that window).
#[cfg(test)]
pub(in crate::afxdp) fn set_materialize_before_claim_hook_for_test(hook: impl FnOnce() + 'static) {
    MATERIALIZE_BEFORE_CLAIM_HOOK_19153.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_materialize_before_claim_hook() {
    let hook = MATERIALIZE_BEFORE_CLAIM_HOOK_19153.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}
