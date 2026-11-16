//! Shared-hit materialize-on-miss (#19153): a worker that misses its own table
//! and finds the flow in the shared map installs the shared row, under the
//! tuple gate's install protocol, from what shared authority holds at the
//! install. Split out of `resolve.rs` (the packet-path resolver), which calls
//! into it after the Owner verdict through
//! [`apply_deferred_shared_materialization`].

use super::*;

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
/// worker install does ([`materialize_capture`]). A refused permit, an absent
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
        ) => (lookup, false),
        // The #10612 miss shape: nothing installed, nothing failed.
        CaptureMaterialize::CaptureFenced
        | CaptureMaterialize::Core(MaterializeOutcome::StaleReplayFenced) => {
            (resolved.lookup.clone(), false)
        }
        CaptureMaterialize::Refused
        | CaptureMaterialize::Core(
            MaterializeOutcome::SharedAbsent
            | MaterializeOutcome::Superseded
            | MaterializeOutcome::InstallRefused,
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
    /// The core ran under the permit.
    Core(MaterializeOutcome),
}

/// #19153: materialize a resolve's capture. Claims the pair, runs
/// [`materialize_current_shared_under_permit`] with the capture's identity as
/// the expected incarnation, and drops the permit.
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
    let outcome = materialize_current_shared_under_permit(
        sessions,
        shared_sessions,
        forwarding,
        &captured.key,
        Some(CapturedIncarnation::of(captured)),
        install_inputs,
        &install_permits,
    );
    drop(install_permits);
    CaptureMaterialize::Core(outcome)
}

/// #19153 fold 1 (Codex P1): what a materialize means for THIS packet, whose
/// resolve, Owner verdict and deferred effects (the promotion, the forwarding
/// revalidation) were all derived from the capture.
///
/// The rule: a promotion may publish only content equal to what the worker
/// row holds after the materialize. When the installed decision and metadata
/// (what a promotion writes) equal the capture's, the capture-derived effects
/// describe the installed row and stand. Otherwise they are dropped, the
/// packet is kept out of the flow cache, and the next packet resolves the
/// installed row as an ordinary worker hit and promotes it: two packets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) enum MaterializeDivergence {
    /// Installed content equal to the capture, or no materialize ran, or one
    /// of the pre-#19153-fold arms (a refusal, the #10612 fence) whose packet
    /// handling is unchanged.
    #[default]
    None,
    /// The installed row differs from the capture only in fields that cannot
    /// change this packet's translation, egress or admission
    /// ([`materialize_divergence`] lists them). The packet forwards once on
    /// the capture's decision; the promotion and the forwarding revalidation
    /// are dropped and the flow cache is not seeded.
    ForwardOnce,
    /// The installed row differs in the decision (NAT, routing table,
    /// resolution: disposition and egress) or in metadata that names the
    /// packet's translation, egress or authority; or the captured incarnation
    /// is gone (shared absent) or replaced (superseded: another NAT or
    /// session id). The packet is NOT forwarded on the capture's decision: the
    /// poll path recycles its frame, as the input-filter drop after the Owner
    /// verdict does. The next packet resolves current state.
    Drop,
}

impl MaterializeDivergence {
    /// Whether this packet must stay out of the flow cache.
    pub(in crate::afxdp) fn suppresses_flow_cache_seed(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// #19153 fold 1: classify how the installed `decision`/`metadata` differ
/// from the capture's. Every `SessionMetadata` field is named (no `..`), so a
/// new field fails to compile until it is classified here.
///
/// Forwarding-relevant (any difference is `Drop`):
/// - the whole `SessionDecision` (resolution: disposition, egress, next hop;
///   the NAT decision; the install table domain and check);
/// - `ingress_zone`, `egress_zone`, `ingress_zone_check`, `egress_zone_check`
///   (the admitting zone pair and its vintage: the Owner verdict and policy);
/// - `ingress_ifindex`, `ingress_vlan_id`, `forward_ingress_vlan_id` (the
///   ingress identity a reply leaves through);
/// - `nat_scope_ifindex`, `nat64_reverse` (translation);
/// - `owner_rg_id`, `fabric_ingress` (HA ownership and fabric redirect);
/// - `is_reverse`, `forward_wire_alias_origin` (direction and alias
///   provenance);
/// - `policy_id` (the admitting policy: authority).
///
/// Metadata-only (`ForwardOnce`): `log_session_init`, `log_session_close`
/// (session logging), `inactivity_timeout_ns` (idle timeout),
/// `policy_counter_idx`, `policy_counter` (hit-counter attribution). None of
/// them changes where this packet goes or how it is translated.
pub(in crate::afxdp) fn materialize_divergence(
    captured_decision: &SessionDecision,
    captured: &SessionMetadata,
    installed_decision: &SessionDecision,
    installed: &SessionMetadata,
) -> MaterializeDivergence {
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
    } = installed;
    let forwarding_differs = installed_decision != captured_decision
        || *ingress_zone != captured.ingress_zone
        || *egress_zone != captured.egress_zone
        || *ingress_zone_check != captured.ingress_zone_check
        || *egress_zone_check != captured.egress_zone_check
        || *ingress_ifindex != captured.ingress_ifindex
        || *ingress_vlan_id != captured.ingress_vlan_id
        || *forward_ingress_vlan_id != captured.forward_ingress_vlan_id
        || *nat_scope_ifindex != captured.nat_scope_ifindex
        || *owner_rg_id != captured.owner_rg_id
        || *fabric_ingress != captured.fabric_ingress
        || *is_reverse != captured.is_reverse
        || *forward_wire_alias_origin != captured.forward_wire_alias_origin
        || *nat64_reverse != captured.nat64_reverse
        || *policy_id != captured.policy_id;
    if forwarding_differs {
        return MaterializeDivergence::Drop;
    }
    let metadata_differs = *log_session_init != captured.log_session_init
        || *log_session_close != captured.log_session_close
        || *inactivity_timeout_ns != captured.inactivity_timeout_ns
        || *policy_counter_idx != captured.policy_counter_idx
        || match (policy_counter, &captured.policy_counter) {
            (Some(left), Some(right)) => !Arc::ptr_eq(left, right),
            (None, None) => false,
            _ => true,
        };
    if metadata_differs {
        MaterializeDivergence::ForwardOnce
    } else {
        MaterializeDivergence::None
    }
}

/// #19153 fold 1: drops of packets whose materialize found the captured
/// incarnation gone, replaced, or installed with forwarding-relevant
/// differences ([`MaterializeDivergence::Drop`]). Internal counter, no log.
pub(in crate::afxdp) static MATERIALIZE_DIVERGENCE_DROPS: AtomicU64 = AtomicU64::new(0);

/// Bump [`MATERIALIZE_DIVERGENCE_DROPS`] for one recycled packet.
pub(in crate::afxdp) fn note_materialize_divergence_drop() {
    MATERIALIZE_DIVERGENCE_DROPS.fetch_add(1, Ordering::Relaxed);
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

/// #19153: the per-packet install inputs of a materialize.
#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct MaterializeInstall {
    pub(in crate::afxdp) now_ns: u64,
    /// The packet's TCP flags, stamped on the installed row.
    pub(in crate::afxdp) tcp_flags: u8,
    /// #16217: the replica may replace a non-peer-synced local incumbent.
    pub(in crate::afxdp) fabric_adopted: bool,
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
/// earlier copy. `expected` (a resolve's capture) only decides whether the
/// caller's packet resolved against this incarnation
/// (`promote::same_synced_incarnation`, the one identity rule); a mismatch is
/// `Superseded` and installs nothing. This is also how the zero-id case is
/// handled: a shared id of 0 matches on the NAT decision alone, and even then
/// the capture is never taken as the row's state. The current row's content is
/// installed, so a legacy peer's same-NAT reuse of the tuple cannot install
/// the stale capture.
///
/// Order: every check runs before the first side effect (joining the
/// publisher's persistent lease hold), so every outcome but `Installed` and
/// `SharedLocal` changes nothing. Lock order is the permits, then the shared
/// lock, as in promotion and the HA import (a lease, then the shared lock).
/// The shared lock is released before the install, and a permit is never
/// waited for, so no cycle exists.
///
/// Cost: runs once per materialize attempt, which is once per flow per worker
/// unless the attempt is refused. A refused attempt is retried by the flow's
/// next packet for as long as its cause lasts. Through `materialize_capture`,
/// a held pair costs the non-allocating claim pre-check (lock operations) and
/// a worker-local #10582 incumbent costs one table probe, both without
/// claiming. A refusal inside this core (a persistent hold that cannot be
/// joined, a directory conflict, a companion the claim does not cover) pays
/// the claim (allocations), the shared re-read and the release on each
/// attempt. No logging.
pub(in crate::afxdp) fn materialize_current_shared_under_permit(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    expected: Option<CapturedIncarnation>,
    install_inputs: MaterializeInstall,
    permits: &[crate::afxdp::bpf_map::InstallPermit],
) -> MaterializeOutcome {
    debug_assert!(
        permits.iter().any(|permit| permit.covers(key)),
        "#19153: materialize under permits that do not fence {key:?}"
    );
    let MaterializeInstall {
        now_ns,
        tcp_flags,
        fabric_adopted,
    } = install_inputs;
    // Re-read under the permits, and copy out only an incarnation the caller
    // may install. One clone, inside the lock.
    let (mut replica, shared_origin) = {
        let shared = lock_shared_recover(shared_sessions);
        let Some(current) = shared.get(key) else {
            return MaterializeOutcome::SharedAbsent;
        };
        if let Some(expected) = expected
            && !super::promote::same_synced_incarnation(
                expected.nat,
                expected.session_id,
                current,
            )
        {
            return MaterializeOutcome::Superseded;
        }
        (synced_replica_entry(current), current.origin)
    };
    let companion_key = reverse_session_key(&replica.key, replica.decision.nat);
    if !permits.iter().any(|permit| permit.covers(&companion_key)) {
        return MaterializeOutcome::InstallRefused;
    }
    // #10612 (N2): the fence judges the content installed.
    if synced_entry_is_stale_replay(shared_origin, &replica.metadata, forwarding) {
        note_stale_replay_fence_drop();
        return MaterializeOutcome::StaleReplayFenced;
    }
    // A zero token carries no leak provenance and is recomputed locally
    // for peer-synced rows. A nonzero token was computed before this
    // shared row was published (and survives demotion), so preserve it as
    // revocation evidence.
    if shared_origin.is_peer_synced() && replica.leak_incarnation == 0 {
        let target = if replica.metadata.is_reverse {
            replica.key.dst_ip
        } else {
            let flow = SessionFlow {
                src_ip: replica.key.src_ip,
                dst_ip: replica.key.dst_ip,
                forward_key: replica.key.clone(),
            };
            resolution_target_for_session(&flow, replica.decision)
        };
        replica.leak_incarnation =
            leak_incarnation_for_session(forwarding, replica.decision, target).unwrap_or(0);
    }
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
            return MaterializeOutcome::InstallRefused;
        }
        Some(hold.with_owner(crate::nat::PersistentLeaseOwner::LocalWorker))
    } else {
        None
    };
    // #17058: build the install via the one shared mapping
    // (`into_session_install`), then apply the materialize overrides:
    // the shared-hit origin and the packet's tcp_flags, and the locally
    // acquired persistent hold (the shared row's hold belongs to its
    // publisher). Every other field (id, close/handshake state,
    // counters, SNAT provenance) is the replica's carried value.
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
    install.tcp_flags = tcp_flags;
    install.persistent_lease_hold = acquired_persistent_hold;
    let materialized = sessions.upsert_synced_with_origin(
        install,
        fabric_adopted,
    );
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
        return MaterializeOutcome::InstallRefused;
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
    if shared_origin.is_peer_synced() {
        MaterializeOutcome::Installed(lookup)
    } else {
        MaterializeOutcome::SharedLocal(lookup)
    }
}

/// Materialize a shared entry only after the packet's Owner verdict.
///
/// #19153 fold 1 (Codex P1): the resolve captured the shared row, and this
/// packet's Owner verdict, its deferred promotion and its deferred forwarding
/// revalidation were all derived from that capture. The materialize installs
/// what shared holds NOW. So the outcome decides what the packet may still do
/// (`resolved.materialize_divergence`):
///
/// - installed content equal to the capture (`MaterializeDivergence::None`):
///   every capture-derived effect describes the installed row and stands;
/// - installed content differing only in metadata that cannot change this
///   packet's translation, egress or admission (`ForwardOnce`): the packet
///   forwards once on the capture's decision, and the promotion and the
///   revalidation are dropped, so neither writes the capture's content over
///   the installed row; the seed is suppressed;
/// - installed content differing in anything else, or the captured
///   incarnation absent or superseded in shared (`Drop`): the same drops, and
///   the poll site recycles the packet instead of forwarding it on a decision
///   shared no longer names.
///
/// The next packet resolves the installed row as a worker hit (or current
/// shared state) and promotes normally: two packets.
///
/// Every `deferred_*` effect of `ResolvedFlowSessionDecision`, on a
/// divergence:
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
///   hit (`ResolvedSessionLookup::shared`), so nothing is replayed.
///
/// Refusals keep their pre-fold handling: the packet forwards on the capture
/// (`install_failed`, seed suppressed, promotion dropped), and the #10612
/// fence keeps its miss shape.
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
    let (install_failed, divergence) = match materialize_capture(
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
        CaptureMaterialize::Core(
            MaterializeOutcome::Installed(installed) | MaterializeOutcome::SharedLocal(installed),
        ) => (
            false,
            materialize_divergence(
                &captured.decision,
                &captured.metadata,
                &installed.decision,
                &installed.metadata,
            ),
        ),
        CaptureMaterialize::CaptureFenced
        | CaptureMaterialize::Core(MaterializeOutcome::StaleReplayFenced) => {
            (false, MaterializeDivergence::None)
        }
        CaptureMaterialize::Refused
        | CaptureMaterialize::Core(MaterializeOutcome::InstallRefused) => {
            (true, MaterializeDivergence::None)
        }
        CaptureMaterialize::Core(
            MaterializeOutcome::SharedAbsent | MaterializeOutcome::Superseded,
        ) => (true, MaterializeDivergence::Drop),
    };
    resolved.install_failed = install_failed;
    resolved.materialize_divergence = divergence;
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
