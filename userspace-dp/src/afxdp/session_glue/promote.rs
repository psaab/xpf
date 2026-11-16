use super::*;

/// #16185: the conntrack map fd pair that travels with the shared
/// session maps. `v4`/`v6` are named fields at one construction site
/// (instead of two bare `c_int` arguments at every call), so the
/// pair is built once and reviewed once. Named fields do not make
/// a same-typed transposition uncompilable (`v4: <v6 fd>` still
/// type-checks); the wiring cells in
/// `shared_session_refs_16185_tests.rs` pin the IPv4 fd to its
/// consumers (the IPv6 fd has no wiring cell; both cells drive
/// IPv4 keys through the v4 test fd). `-1` means unavailable
/// (no-op), matching the
/// pre-bundle scalar convention.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct ConntrackFds {
    pub v4: c_int,
    pub v6: c_int,
}

/// #16185: one packet's two clocks. `ns` (monotonic nanoseconds) and
/// `secs` (seconds for the HA-lease checks in the resolve path) are
/// two readings of the same monotonic clock: `secs == ns / 1_000_000_000`.
/// #17069: construction is only through [`Tick::from_ns`], which
/// derives `secs` from `ns`, so the pairing the bundle asserts cannot
/// be broken by a zero-filled or independently sampled `secs`. The
/// sole `secs` reader is the resolve path (`resolve.rs` reads
/// `shared.tick.secs` for `should_keep_synced_hit_transient` and the
/// HA forwarding-active checks); teardown/housekeeping bundles fed
/// through this constructor therefore carry the real seconds value
/// instead of the pre-#17069 `secs: 0`, which would have read every
/// non-zero HA lease as active (fail-open at time 0) had a teardown
/// consumer ever read it. `Tick` carries only these two: the HA
/// startup-grace deadline stays a separate named argument because it
/// is a deadline, not a clock reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) struct Tick {
    pub ns: u64,
    pub secs: u64,
}

impl Tick {
    /// The only clock constructor: both fields from one monotonic
    /// reading, `secs` derived so the two can never disagree.
    pub(in crate::afxdp) fn from_ns(ns: u64) -> Self {
        Self {
            ns,
            secs: ns / 1_000_000_000,
        }
    }

    /// Test-only decoupled clock: HA-lease cells need a `secs` that
    /// `from_ns` cannot express (e.g. `ns: 1_000_000, secs: 1_000`
    /// against a lease expiring at 500). Production has no caller:
    /// every production bundle goes through `from_ns`, so the
    /// `secs == ns / 1_000_000_000` invariant holds outside tests.
    #[cfg(test)]
    pub(in crate::afxdp) fn from_parts(ns: u64, secs: u64) -> Self {
        Self { ns, secs }
    }
}

/// Shared-session backing references that travel together at every
/// site that touches synced sessions. Grouping them collapses the
/// 16-param `maybe_promote_synced_session` and 10-param
/// `purge_translated_synced_hit` signatures that triggered #1346.
/// (Issue body rounded these to 17/11 by counting `&mut sessions`
/// as a leading param; the actual `fn` declarations on
/// `origin/master` carry 16 and 10 typed args respectively.)
///
/// #16185 extends this existing bundle - deliberately NOT a parallel
/// `SharedSessionCtx` - with the groupings that travel with the
/// shared maps at the resolve/teardown call sites: the peer/command
/// queues, `conntrack` ([`ConntrackFds`]) and `tick` ([`Tick`]).
/// `session_map` stays a separate argument: it is the caller's
/// per-binding steering handle, not shared-map wiring, and
/// `WorkerContext` keeps owning the broader poll context.
/// `worker_commands_by_id` is normalised to `&WorkerCommandQueues`
/// here (the type `resolve_*`/`promote.rs` already used); the
/// `delete_terminal_*` twins previously took the bare
/// `&BTreeMap<...>` deref target, so this also closes the validator
/// open check on the two queue-map types with one answer.
///
/// `Copy` because the struct is 6 `&`-references plus two small
/// `Copy` value groupings (conntrack fd pair + tick) with no
/// destructor. Passing it by value should compile to the same
/// register/stack use vs. passing the fields individually. Note:
/// `cargo-asm 0.1.16` panics parsing this codebase's symbols, so a
/// programmatic before/after asm diff was not produced. The
/// zero-cost claim rests on the structural argument (Copy +
/// pointer-sized fields + no Drop) and is empirically gated by the
/// iperf witness in the PR.
#[derive(Clone, Copy)]
pub(in crate::afxdp) struct SharedSessionRefs<'a> {
    pub sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
    pub peer_worker_commands: &'a [Arc<Mutex<VecDeque<WorkerCommand>>>],
    pub worker_commands_by_id: &'a WorkerCommandQueues,
    pub conntrack: ConntrackFds,
    pub tick: Tick,
}

impl<'a> SharedSessionRefs<'a> {
    /// The no-conntrack, no-clock bundle for callers that only carry
    /// the shared maps (the old `-1, -1` scalar convention):
    /// conntrack fds `-1` (unavailable) and a zero tick. Production
    /// poll sites construct the full struct literally so every field
    /// is visible at the call site.
    pub(in crate::afxdp) fn detached(
        sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
        peer_worker_commands: &'a [Arc<Mutex<VecDeque<WorkerCommand>>>],
        worker_commands_by_id: &'a WorkerCommandQueues,
    ) -> Self {
        Self {
            sessions,
            nat_sessions,
            forward_wire_sessions,
            owner_rg_indexes,
            peer_worker_commands,
            worker_commands_by_id,
            conntrack: ConntrackFds { v4: -1, v6: -1 },
            tick: Tick::from_ns(0),
        }
    }

    /// This bundle with different conntrack fds and tick (the
    /// `_with_conntrack` entry points receive the fds/clock from
    /// their caller and graft them onto the shared-map bundle).
    pub(in crate::afxdp) fn with_conntrack_tick(
        mut self,
        conntrack: ConntrackFds,
        tick: Tick,
    ) -> Self {
        self.conntrack = conntrack;
        self.tick = tick;
        self
    }
}

/// Predicate: is `key` the forward (NAT-translated) side of a
/// synced session? Used to distinguish translated forward hits from
/// reverse-side hits when deciding whether to purge a transient
/// peer-synced entry.
pub(in crate::afxdp::session_glue) fn is_translated_forward_session_key(
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
) -> bool {
    if metadata.is_reverse {
        return false;
    }
    decision.nat.rewrite_src == Some(key.src_ip) || decision.nat.rewrite_dst == Some(key.dst_ip)
}

/// Predicate: should a peer-synced hit be kept as transient (i.e.
/// purged from the shared maps so the local node re-resolves) rather
/// than being installed locally? True when the local node is not the
/// active owner of the session's RG and the key is the translated
/// forward side.
pub(in crate::afxdp::session_glue) fn should_keep_synced_hit_transient(
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) -> bool {
    origin.is_peer_synced()
        && !owner_rg_is_locally_active(ha_state, metadata.owner_rg_id, now_secs)
        && is_translated_forward_session_key(key, decision, metadata)
}

// #18552 test seam: runs once, on the promoting thread, after the worker row
// flipped to `SharedPromote` and before the shared publish. That is the window
// the coordinator's #9678 gate cannot see (it reads only the shared row), so a
// cell can drive a peer import into it deterministically.
#[cfg(test)]
std::thread_local! {
    static PROMOTE_AFTER_FLIP_HOOK_18552: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(in crate::afxdp) fn set_promote_after_flip_hook_for_test(hook: impl FnOnce() + 'static) {
    PROMOTE_AFTER_FLIP_HOOK_18552.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_promote_after_flip_hook() {
    let hook = PROMOTE_AFTER_FLIP_HOOK_18552.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

// #18552 (review F4b) test seam: runs once, on the promoting thread, after the
// shared publish and before the sibling fan-out (`replicate_session_upsert`).
// A cell probes the tuple gate here to pin that the install permit is still
// held while the fan-out is queued.
#[cfg(test)]
std::thread_local! {
    static PROMOTE_BEFORE_FANOUT_HOOK_18552: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(in crate::afxdp) fn set_promote_before_fanout_hook_for_test(hook: impl FnOnce() + 'static) {
    PROMOTE_BEFORE_FANOUT_HOOK_18552.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_promote_before_fanout_hook() {
    let hook = PROMOTE_BEFORE_FANOUT_HOOK_18552.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

/// #18552 (review F2) and #19153: THE synced-incarnation identity rule. This
/// is the single place it lives. Both callers use it:
///
/// - #18552 promotion (`synced_row_incarnation`) judges the worker row (`nat`,
///   `session_id`) against the current shared row `entry`;
/// - #19153 materialize-on-miss (`materialize_current_shared_under_permit`)
///   judges the shared row it captured at resolve time against the current
///   shared row `entry`, re-read under its install permit.
///
/// It answers "not provably a different incarnation": `entry` passes iff its
/// NAT decision equals `nat` (mandatory, always compared) and, when
/// `entry.session_id` is non-zero, its session id equals `session_id`.
///
/// Identity is the RT_FLOW session id plus the NAT decision: the two fields
/// both the worker row and `SyncedSessionEntry` carry. The worker row does not
/// store the peer's install generation, and a same-incarnation resend bumps
/// the generation (the peer stamps every send from one climbing counter), so
/// generation is deliberately not compared: such a resend is the same
/// incarnation. A new incarnation of a reused 5-tuple carries a different
/// session id, and a translation change a different NAT decision; either is a
/// different incarnation.
///
/// A shared session id of 0 is the unknown/legacy sentinel (a peer that
/// predates the field). Then only the NAT decision is compared, and a pass is
/// NOT proof of sameness (#18552 cycle 2, Codex P2): a legacy peer can replace
/// or delete-and-recreate a tuple under the same translation. The worker never
/// stores 0 (it mints a node-local id, `session/install.rs`), so nothing can
/// match it. No caller treats a zero-id pass as equality:
/// `synced_row_incarnation` reports it `Unproven` and promotion reconciles the
/// worker row from CURRENT shared content first; the #19153 materialize core
/// always installs current shared content, never its caller's copy.
pub(in crate::afxdp) fn same_synced_incarnation(
    nat: NatDecision,
    session_id: u64,
    entry: &SyncedSessionEntry,
) -> bool {
    entry.decision.nat == nat && (entry.session_id == 0 || entry.session_id == session_id)
}

/// #18552 (review F2): which incarnation the SHARED row for `key` names,
/// judged against THIS worker's row for `key`, by [`same_synced_incarnation`]
/// (the session id plus the NAT decision, never the generation). A
/// same-incarnation resend is `Current`; a new incarnation of a reused 5-tuple
/// or a translation change is `Superseded`. #18552 cycle 2 (Codex P2): a
/// peer-synced shared row with the zero (unknown) session id and the same NAT
/// is `Unproven`, never `Current`.
///
/// Called under the promotion's install permit, which excludes every import
/// and delete lease of the tuple, so the answer holds until the permit drops.
/// The caller keys the reverse/forward question itself: this helper is
/// direction-agnostic and judges exactly the row stored under `key`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::afxdp) enum SyncedRowIncarnation {
    /// Shared names this worker row's incarnation and is still peer-synced.
    Current,
    /// This worker has no row under `key`.
    WorkerAbsent,
    /// No shared row under `key`: a completed delete whose `DeleteSynced` is
    /// still queued for this worker.
    SharedAbsent,
    /// Shared names a different incarnation (session id or NAT differs): a
    /// completed import whose `UpsertSynced` is still queued for this worker.
    Superseded,
    /// Shared names this incarnation but already as locally owned (a sibling's
    /// `SharedPromote`, whose replicated upsert is queued for this worker).
    SharedLocal,
    /// #18552 cycle 2 (Codex P2): shared is a peer-synced row under the same
    /// NAT decision but carries the zero (unknown) session id, so it cannot
    /// prove the worker row is its incarnation. A legacy peer's same-NAT
    /// replacement, or delete and recreate, whose worker command is still
    /// queued, looks exactly like this. Promotion reconciles the worker row
    /// from the CURRENT shared content before it flips anything.
    Unproven,
}

pub(in crate::afxdp) fn synced_row_incarnation(
    sessions: &SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) -> SyncedRowIncarnation {
    let Some((session_id, nat)) = sessions.ct_slice_emit_identity_for(key) else {
        return SyncedRowIncarnation::WorkerAbsent;
    };
    let shared = lock_shared_recover(shared_sessions);
    match shared.get(key) {
        None => SyncedRowIncarnation::SharedAbsent,
        Some(entry) if !same_synced_incarnation(nat, session_id, entry) => {
            SyncedRowIncarnation::Superseded
        }
        Some(entry) if !entry.origin.is_peer_synced() => SyncedRowIncarnation::SharedLocal,
        Some(entry) if entry.session_id == 0 => SyncedRowIncarnation::Unproven,
        Some(_) => SyncedRowIncarnation::Current,
    }
}

/// #18552 cycle 2: bring the worker row under `key` to the CURRENT shared
/// content, under the promotion's own permits, through the #19153 materialize
/// core (`materialize_current_shared_under_permit`). `expected` is the
/// identity the caller judged shared against: the worker row's when it holds
/// one, the shared row's own when it does not. Only `Installed` (a peer-synced
/// replica of current shared content) lets the promotion go on; every other
/// outcome is the promotion's skip, and leaves the row as the core left it: a
/// consistent synced replica of current shared content (`SharedLocal`: a
/// `WorkerLocalImport` replica, which is "do not promote"), or untouched.
fn reconcile_from_shared(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    expected: CapturedIncarnation,
    install_inputs: MaterializeInstall,
    permits: &[crate::afxdp::bpf_map::InstallPermit],
) -> Result<(), SyncedPromotion> {
    // Identity only (`classify_against` `None`, #19153 fold 2): the core then
    // reports `MaterializeDivergence::None` on every path and installs with
    // `install_inputs` unchanged, as before fold 2. Rule (b) for a hit row
    // compares after the install (`reconcile_unproven_row`); an absent F has
    // nothing of this packet's to compare or to take (its inputs carry no
    // flags and no adoption).
    let (outcome, _) = materialize_current_shared_under_permit(
        sessions,
        shared_sessions,
        forwarding,
        key,
        Some(expected),
        None,
        install_inputs,
        permits,
    );
    match outcome {
        MaterializeOutcome::Installed(_) => Ok(()),
        MaterializeOutcome::SharedLocal(_) => {
            Err(SyncedPromotion::NotCurrent(SyncedRowIncarnation::SharedLocal))
        }
        MaterializeOutcome::SharedAbsent => {
            Err(SyncedPromotion::NotCurrent(SyncedRowIncarnation::SharedAbsent))
        }
        MaterializeOutcome::Superseded => {
            Err(SyncedPromotion::NotCurrent(SyncedRowIncarnation::Superseded))
        }
        MaterializeOutcome::StaleReplayFenced => Err(SyncedPromotion::StaleReplayFenced),
        MaterializeOutcome::InstallRefused => Err(SyncedPromotion::ReconcileRefused),
    }
}

/// #18552 cycle 2, rule (b): reconcile an `Unproven` worker row (a zero shared
/// session id proves nothing) from the CURRENT shared content, then apply the
/// same equality test as the #19153 materialize (`materialize_divergence`): the
/// worker row's stored decision and metadata, which this packet was resolved
/// against and would promote, against what the reconcile installed, on every
/// peer-authored field (the resolution and the owner RG are this node's own
/// derivations on both paths, see below).
///
/// - Equal: `Ok(())`. The packet's decision and metadata describe the
///   installed row, so promoting the installed row with them publishes exactly
///   what the worker holds.
/// - Different: `ReconcileDiverged`, and nothing is promoted this packet. The
///   row is now a consistent synced replica of current shared content. The next
///   packet resolves that row, the reconcile re-installs identical content, the
///   test passes, and it promotes: two packets, no infinite deferral.
///
/// "Zero-id gets the peer's content" and "promote what was installed" are the
/// same rule here and in the materialize.
fn reconcile_unproven_row(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    install_inputs: MaterializeInstall,
    permits: &[crate::afxdp::bpf_map::InstallPermit],
) -> Result<(), SyncedPromotion> {
    let worker_absent = SyncedPromotion::NotCurrent(SyncedRowIncarnation::WorkerAbsent);
    let Some((stored_decision, stored_metadata, _)) = sessions.entry_with_origin(key) else {
        return Err(worker_absent);
    };
    let Some((session_id, nat)) = sessions.ct_slice_emit_identity_for(key) else {
        return Err(worker_absent);
    };
    reconcile_from_shared(
        sessions,
        shared_sessions,
        forwarding,
        key,
        CapturedIncarnation { nat, session_id },
        install_inputs,
        permits,
    )?;
    // Compare with what the worker row HOLDS after the reconcile, read back:
    // the install can keep this worker's own stamp over the replica's (the
    // #9752 install-table preservation of `upsert_synced_with_origin`), and a
    // compare against the replica would then never pass on any later packet.
    let Some(installed) = sessions.synced_entry_for(key) else {
        return Err(worker_absent);
    };
    // The worker row's resolution and owner RG are this node's own derivations,
    // not peer content: `handle_upsert_synced` re-resolves both from the local
    // FIB at import, and the resolve's forwarding revalidation persists them,
    // while the reconcile installs shared's copies. The promotion writes this
    // packet's fresh resolution and the worker's owner RG anyway. Comparing
    // them would call every unchanged zero-id row diverged, so they are taken
    // from the installed side and every PEER-authored field is compared.
    //
    // #19153 fold 2: `materialize_divergence` classifies whole synced rows and
    // exempts no field. Rule (b) compares the decision and the metadata, as
    // before: every other field of the stored side is the installed row's, so
    // only a decision or metadata field can differ, and any difference is
    // `Drop` (fold 1's logging/counter-only `ForwardOnce` class is gone).
    let mut stored = installed.clone();
    stored.decision = SessionDecision {
        resolution: installed.decision.resolution,
        ..stored_decision
    };
    stored.metadata = SessionMetadata {
        owner_rg_id: installed.metadata.owner_rg_id,
        ..stored_metadata
    };
    match materialize_divergence(forwarding, &stored, &installed, &mut None) {
        MaterializeDivergence::None => Ok(()),
        divergence => Err(SyncedPromotion::ReconcileDiverged(divergence)),
    }
}

/// #18552 cycle 2: what a reverse hit does with its forward row F.
enum ForwardPartner {
    /// R is promoted alone (forward hit, F not ours, split RG, F not current).
    Alone,
    /// F's decision, metadata and the shared entry to publish, read before any
    /// flip: promote the pair.
    Pair(SessionDecision, SessionMetadata, SyncedSessionEntry),
    /// F was `Unproven` and its reconcile installed content that differs from
    /// the F this worker held (rule (b)). Promoting R alone would leave F
    /// peer-synced with nothing to retry it (Codex P1), so nothing is promoted
    /// this packet; the next reply promotes the pair.
    Diverged,
}

/// #18552 (B1: Codex P1-4 = r24 P2-1(a), the lead's Option B; cycle 2: Codex
/// P1 and P2): the forward row F that a reverse-hit promotion of its companion
/// R promotes with it, under the same permit (which already claims `[R, F]`).
/// Returns F's decision and metadata and the shared entry to publish for it,
/// read BEFORE any flip. `None` means R is promoted alone:
///
/// - `key` is not a reverse companion: forward hits are unchanged, and a
///   forward hit never promotes its reverse;
/// - this worker holds an F that is not a promotable peer row, or whose own
///   companion is not `key`;
/// - F's owner RG is not locally active in `ha_state`, the HA view the hit's
///   own verdict used. In a split RG, F's owner (which holds the source-NAT
///   allocation) stays authoritative for the pair, so its imports and deletes
///   legitimately apply to F; an owner of 0 (unknown) is not "ours" either;
/// - shared authority does not name F's incarnation (`synced_row_incarnation`:
///   absent, superseded, or already local): F is being replaced or deleted, and
///   its queued worker command repairs it.
///
/// Cycle 2. When this worker holds F but shared F carries the zero (unknown)
/// session id (`Unproven`), F is first reconciled from the CURRENT shared
/// content (Codex P2). When this worker holds NO F, but shared F is a
/// peer-synced forward row whose companion is `key` and whose owner RG is
/// locally active, F's import has completed and only its `UpsertSynced` is
/// still queued here (Codex P1). F is materialized from shared now, under the
/// same permit, and promoted with R; the queued upsert later meets a local row
/// and is refused, which is correct. Before cycle 2 the missing F promoted R
/// alone, and R's promotion left nothing to retry F, so shared F stayed
/// peer-synced and both gates stayed blind for the flow's life.
///
/// A reconcile or materialize here installs only a consistent synced replica
/// of current shared content. If R's later flip is declined, F stays exactly
/// that, as the queued upsert would have left it.
///
/// Why F at all: the #9678 import gate and the #9714 peer-delete guard read
/// only the FORWARD row. With R promoted alone, F stayed `SyncImport`, so a
/// late different-translation import of F passed #9678 and freed T1, and a
/// peer delete of F passed #9714 and took R with it.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
fn reverse_hit_forward_partner(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    tick: Tick,
    key: &SessionKey,
    metadata: &SessionMetadata,
    forward_key: &SessionKey,
    permits: &[crate::afxdp::bpf_map::InstallPermit],
) -> ForwardPartner {
    if !metadata.is_reverse {
        return ForwardPartner::Alone;
    }
    // F carries no packet of its own here: the packet belongs to R.
    let install_inputs = MaterializeInstall {
        now_ns: tick.ns,
        tcp_flags: 0,
        fabric_adopted: false,
    };
    match sessions.entry_with_origin(forward_key) {
        Some((forward_decision, forward_metadata, forward_origin)) => {
            if !forward_origin.is_promotable_synced()
                || forward_metadata.is_reverse
                || reverse_session_key(forward_key, forward_decision.nat) != *key
                || !owner_rg_is_locally_active(ha_state, forward_metadata.owner_rg_id, tick.secs)
            {
                return ForwardPartner::Alone;
            }
            match synced_row_incarnation(sessions, shared_sessions, forward_key) {
                SyncedRowIncarnation::Current => {}
                SyncedRowIncarnation::Unproven => match reconcile_unproven_row(
                    sessions,
                    shared_sessions,
                    forwarding,
                    forward_key,
                    install_inputs,
                    permits,
                ) {
                    Ok(()) => {}
                    Err(SyncedPromotion::ReconcileDiverged(_)) => return ForwardPartner::Diverged,
                    Err(_) => return ForwardPartner::Alone,
                },
                _ => return ForwardPartner::Alone,
            }
        }
        None => {
            // Codex P1: F absent here. Only a current, peer-synced, locally
            // owned shared F that pairs with R is materialized. F's flip then
            // writes the content this materialize installed (read back below),
            // so there is nothing for rule (b) to compare.
            let expected = {
                let shared = lock_shared_recover(shared_sessions);
                let Some(shared_forward) = shared.get(forward_key) else {
                    return ForwardPartner::Alone;
                };
                if !shared_forward.origin.is_promotable_synced()
                    || shared_forward.metadata.is_reverse
                    || reverse_session_key(forward_key, shared_forward.decision.nat) != *key
                    || !owner_rg_is_locally_active(
                        ha_state,
                        shared_forward.metadata.owner_rg_id,
                        tick.secs,
                    )
                {
                    return ForwardPartner::Alone;
                }
                CapturedIncarnation::of(shared_forward)
            };
            if reconcile_from_shared(
                sessions,
                shared_sessions,
                forwarding,
                forward_key,
                expected,
                install_inputs,
                permits,
            )
            .is_err()
            {
                return ForwardPartner::Alone;
            }
        }
    }
    // Judge the row that will flip, which a materialize above may have just
    // installed: still the forward half of this pair, still owned here.
    let Some((forward_decision, forward_metadata, _)) = sessions.entry_with_origin(forward_key)
    else {
        return ForwardPartner::Alone;
    };
    if forward_metadata.is_reverse
        || reverse_session_key(forward_key, forward_decision.nat) != *key
        || !owner_rg_is_locally_active(ha_state, forward_metadata.owner_rg_id, tick.secs)
    {
        return ForwardPartner::Alone;
    }
    let Some(mut forward_entry) = sessions.synced_entry_for(forward_key) else {
        return ForwardPartner::Alone;
    };
    forward_entry.origin = SessionOrigin::SharedPromote;
    ForwardPartner::Pair(forward_decision, forward_metadata, forward_entry)
}

/// #18552: what one synced-promotion attempt did. Every outcome other than
/// `Promoted` leaves the worker row, shared authority, the conntrack origin
/// bit, steering and the sibling queues exactly as they were: every check runs
/// before the flip, so no return path can leave the worker row `SharedPromote`
/// with the shared row still peer-synced (review r24 P2-1(b)).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::afxdp) enum SyncedPromotion {
    /// Not promotable, or not a `ForwardCandidate` (the pre-#18552 no-op).
    NotAttempted,
    Promoted,
    /// TRANSIENT: the install claim on the pair was refused. The row stays
    /// promotable and only a resolved hit retries it.
    Deferred,
    /// TERMINAL: the #10612 stale-replay fence (the row's zones vanished).
    StaleReplayFenced,
    /// TERMINAL: shared authority no longer names this row's incarnation.
    NotCurrent(SyncedRowIncarnation),
    /// The worker-row flip did not apply (the pre-#18552 no-op).
    FlipDeclined,
    /// TRANSIENT (cycle 2): the hit row was `Unproven` (zero shared id) and its
    /// reconcile from current shared content was refused by the install
    /// itself (`MaterializeOutcome::InstallRefused`). The worker row is
    /// unchanged and still unproven.
    ReconcileRefused,
    /// TRANSIENT (cycle 2, rule (b)): the hit row (or the reverse hit's F) was
    /// `Unproven`, and its reconcile installed content that differs from what
    /// this packet was resolved against (`materialize_divergence`). Nothing was
    /// promoted; the next packet promotes the reconciled row. A `Drop`
    /// divergence of the hit row also keeps THIS packet from being forwarded
    /// (the maybe-promote caller copies it into
    /// `resolved.materialize_divergence`).
    ReconcileDiverged(MaterializeDivergence),
}

impl SyncedPromotion {
    /// #18552 (review F1): whether THIS packet must not seed the flow cache.
    /// Flow-cache hits never promote (`flow_cache_hit.rs`) and forwarding
    /// entries never TTL-expire, so a seeded deferral is never retried.
    ///
    /// - `Deferred` suppresses: the refusal lasts as long as its holder, so the
    ///   next packet must resolve and retry.
    /// - `NotCurrent(Superseded)` suppresses: the replacing `UpsertSynced` is
    ///   queued and lands at this worker's next command drain, which bounds it.
    ///   A cache hit checks only that the backing row is live, not its
    ///   incarnation, so an entry seeded from the superseded row would keep
    ///   serving the old decision after the repair and never promote it.
    /// - `NotCurrent(SharedAbsent)` does not: the queued `DeleteSynced` evicts
    ///   the key's cache entries itself (#6457). If no delete were queued,
    ///   suppression would cost a slow-path trip per packet with no end.
    /// - `NotCurrent(SharedLocal)` does not: shared already records local
    ///   ownership, so the #9678 and #9714 gates hold, and the sibling's queued
    ///   upsert makes this row non-promotable; the incarnation is the same.
    /// - `StaleReplayFenced` does not: the fence is permanent until a purge
    ///   removes the row, so suppression would be unbounded.
    /// - `ReconcileDiverged` suppresses (cycle 2, rule (b)): the next packet
    ///   must resolve the reconciled row and promote it; a cache hit never
    ///   promotes.
    /// - `ReconcileRefused` suppresses (cycle 2): the row is a zero-id row
    ///   shared cannot prove current, so a seeded entry could keep serving a
    ///   stale incarnation's decision after the queued repair, exactly as for
    ///   `Superseded`.
    /// - The rest change nothing a later hit could retry.
    pub(in crate::afxdp) fn suppresses_flow_cache_seed(self) -> bool {
        matches!(
            self,
            Self::Deferred
                | Self::NotCurrent(SyncedRowIncarnation::Superseded)
                | Self::ReconcileRefused
                | Self::ReconcileDiverged(_)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::afxdp) enum SessionHitVerdict {
    Owner,
    Foreign,
    Unresolved,
}

/// Promote a synced session hit into a locally-owned session when
/// the local node is now the active owner. No-op if the session is
/// not promotable or not currently in a `ForwardCandidate` state.
///
/// On successful promotion, the session is re-published to the
/// kernel session map, mirrored into the shared maps under
/// `SharedPromote` origin, and replicated to peer worker commands.
///
/// #18552: the worker-row flip, the shared publish and the sibling fan-out run
/// under the worker install permit for the session key and its reply tuple,
/// taken without blocking. Without it a peer import could run between the flip
/// and the publish, see the older peer row in the shared map, pass the
/// coordinator's #9678 ownership gate and retire the flow's live NAT
/// allocation. Every check runs BEFORE the flip, so an outcome other than
/// `Promoted` changes nothing:
///
/// - TRANSIENT, `Deferred`: the install claim is refused. The holder is an HA
///   import, delete, pressure-shed, policy-batch or mirror-only lease; a
///   sibling worker's install, close-barrier or GC-teardown permit; a
///   `with_publish` BPF publisher; a full gate shard; or a map-wide clear
///   fence. A non-allocating pre-check (`install_claim_would_refuse`) refuses
///   the common case before `try_acquire_installs` allocates. The packet
///   forwards on the synced hit, the row stays promotable, and the caller
///   keeps this packet out of the flow cache, so the next resolved hit
///   retries (`resolve.rs` arms a deferred promotion on every such hit).
/// - TERMINAL, `StaleReplayFenced` (#10612) or `NotCurrent`: under the permit,
///   the shared row no longer names this worker row's incarnation (it was
///   replaced or deleted, and the worker command that repairs this row is
///   still queued), or a sibling already promoted it. A later hit after the
///   repair promotes the current incarnation.
///
/// #18552 cycle 2, judged under the permit (`synced_row_incarnation`), for the
/// hit row:
///
/// | shared vs the worker row | action |
/// |---|---|
/// | proven current: same NAT, shared id non-zero and equal | promote the worker row as before (its last-seen, TCP state and counters are kept) |
/// | `Unproven`: same NAT, shared id 0 | reconcile the row from CURRENT shared content, then rule (b) (`reconcile_unproven_row`): installed content equal to what this packet resolved against promotes the installed row; otherwise nothing this packet (`ReconcileDiverged`, seed suppressed, the packet dropped) and the next packet promotes |
/// | `Superseded` (NAT, or the non-zero id, differs) | skip; the seed is suppressed |
/// | absent, `SharedLocal`, stale-replay fenced | skip |
///
/// and for a reverse hit's forward F (`reverse_hit_forward_partner`): F proven
/// current is promoted with R; F `Unproven` is reconciled under rule (b), then
/// promoted with R if equal, else nothing is promoted this packet (R alone
/// would leave nothing to retry F); F ABSENT here while shared F is current,
/// peer-synced and locally owned
/// (its `UpsertSynced` still queued, Codex P1) is materialized from shared,
/// then promoted with R; in a split RG (F's owner RG not active here) only R is
/// promoted. No row flips until every R and F check has passed. A reconcile or
/// materialize that is followed by a failed check or a declined flip leaves a
/// consistent synced replica of current shared content, the row the queued
/// worker command would have installed, never a half-promoted one.
///
/// [`SyncedPromotion::suppresses_flow_cache_seed`] says which outcomes keep
/// the packet out of the flow cache, and why.
///
/// #18552 (B1): the import and peer-delete gates read only the FORWARD row, so
/// a reverse hit also promotes its forward F with R, under the same permit,
/// when F is ours and current ([`reverse_hit_forward_partner`]); otherwise R is
/// promoted alone. In a split RG (F's owner RG not active here) F's owner,
/// which holds the source-NAT allocation, stays authoritative for the pair, so
/// its imports and deletes of F apply. A forward hit never promotes its reverse.
///
/// The compatibility wrapper keeps the pre-#1346 13-argument shape for tests;
/// the production variant adds the two conntrack fds to invalidate only origin.
fn promote_synced_session_with_conntrack(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    fabric_ingress: bool,
    protocol: u8,
    tcp_flags: u8,
    ack: Option<u32>,
) -> (SessionMetadata, SyncedPromotion) {
    if !origin.is_promotable_synced()
        || decision.resolution.disposition != ForwardingDisposition::ForwardCandidate
    {
        return (metadata, SyncedPromotion::NotAttempted);
    }

    let mut promoted = metadata;
    if promoted.owner_rg_id <= 0 {
        promoted.owner_rg_id = owner_rg_for_resolution(forwarding, decision.resolution);
    }
    if fabric_ingress {
        promoted.fabric_ingress = true;
    }
    // #10612 (M4): fence stale replays before anything changes. A row that
    // lingered through an unvalidated purge (purge no-op) must not be flipped
    // or published to shared/BPF/peer after its zones vanished. #18552 (review
    // r24 P2-1(b)): this used to run after the flip and return with the worker
    // row `SharedPromote` and the shared row still peer-synced. The fence reads
    // only the promoted metadata and the zone set, so it needs no permit.
    if crate::afxdp::session_glue::synced_entry_is_stale_replay(
        SessionOrigin::SharedPromote,
        &promoted,
        forwarding,
    ) {
        crate::afxdp::session_glue::note_stale_replay_fence_drop();
        return (promoted, SyncedPromotion::StaleReplayFenced);
    }
    // #18552: hold the install permit from before the flip until the shared
    // publish and the sibling fan-out are done. An import's tuple lease then
    // either refuses this promotion or waits for it and re-reads a shared row
    // that is already `SharedPromote`, which its #9678 gate stops. Never
    // blocks: a refusal changes nothing and the next resolved hit retries.
    // `companion_key` is the other half of the pair: the reply tuple for a
    // forward hit, the forward tuple for a reverse hit.
    let companion_key = reverse_session_key(key, decision.nat);
    let gate = crate::afxdp::bpf_map::global_tuple_gate();
    // Review r24 P3-1: refuse without allocating while a holder lasts.
    if gate.install_claim_would_refuse(&[key, &companion_key]) {
        return (promoted, SyncedPromotion::Deferred);
    }
    let Ok(install_permits) = gate.try_acquire_installs([key.clone(), companion_key.clone()])
    else {
        return (promoted, SyncedPromotion::Deferred);
    };
    // #18552 (review F2): an import or delete that completed BEFORE the permit
    // was taken has already rewritten shared authority and queued this
    // worker's repair. The worker row is then a superseded (or deleted)
    // incarnation, and promoting it would overwrite the current shared row and
    // make the queued repair be refused as a local-ownership clobber. Promote
    // only the incarnation shared still names.
    //
    // #18552 cycle 2 (Codex P2): a zero shared id proves nothing, so an
    // `Unproven` row is first reconciled from the CURRENT shared content under
    // this permit, and rule (b) applies (`reconcile_unproven_row`): the
    // installed content must equal what this packet was resolved against, or
    // nothing is promoted this packet. A row shared proves current (non-zero
    // id, same NAT) is promoted as before and keeps its worker-local last-seen,
    // TCP state and counters.
    match synced_row_incarnation(sessions, shared.sessions, key) {
        SyncedRowIncarnation::Current => {}
        SyncedRowIncarnation::Unproven => {
            if let Err(outcome) = reconcile_unproven_row(
                sessions,
                shared.sessions,
                forwarding,
                key,
                MaterializeInstall {
                    now_ns: shared.tick.ns,
                    tcp_flags,
                    fabric_adopted: false,
                },
                &install_permits,
            ) {
                return (promoted, outcome);
            }
        }
        incarnation => return (promoted, SyncedPromotion::NotCurrent(incarnation)),
    }
    // #18552 (B1): a reverse hit promotes its forward F too, when F is ours
    // and current. Decided here, with every R check, before ANY flip; when F
    // does not qualify, R is promoted alone. Cycle 2: F absent here but
    // current in shared is materialized, and a zero-id F is reconciled under
    // rule (b), under this same permit (`reverse_hit_forward_partner`). A
    // diverged F defers the whole promotion: R alone would leave nothing to
    // retry F.
    let forward_partner = match reverse_hit_forward_partner(
        sessions,
        shared.sessions,
        forwarding,
        ha_state,
        shared.tick,
        key,
        &promoted,
        &companion_key,
        &install_permits,
    ) {
        ForwardPartner::Alone => None,
        ForwardPartner::Pair(forward_decision, forward_metadata, forward_entry) => {
            Some((forward_decision, forward_metadata, forward_entry))
        }
        // R itself is current and this packet resolved against it, so the
        // packet forwards (`None`; fold 1 named this `ForwardOnce`, which
        // #19153 fold 2 removed); `ReconcileDiverged` drops the promotion and
        // the revalidation and suppresses the seed, and the next reply
        // retries the pair.
        ForwardPartner::Diverged => {
            return (
                promoted,
                SyncedPromotion::ReconcileDiverged(MaterializeDivergence::None),
            );
        }
    };
    // #13939/#17092: `promote_synced_with_origin` strips any FIN/RST; the
    // Owner-only `Defer::None` replay (`apply_deferred_owner_hit`) after the
    // authority verdict re-applies the close and propagates it.
    if !sessions.promote_synced_with_origin(SessionUpdate {
        key,
        decision,
        metadata: promoted.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns: shared.tick.ns,
        protocol,
        tcp_flags,
        ack,
    }) {
        return (promoted, SyncedPromotion::FlipDeclined);
    }
    // #17058: build from the live row via the one shared construction,
    // then apply the promote overrides (origin, promoted metadata,
    // decision, protocol and the packet's tcp_flags). Every other
    // wire field (session_id, close/handshake state, counters,
    // PPTP pair, lease hold, SNAT provenance, leak incarnation) is
    // the live value `synced_entry_for` read in one lookup.
    // `synced_entry_for` leaves sibling recency empty; the shared
    // same-incarnation publish merge preserves the serving sibling's stamp.
    // #18552: read right after the flip, before any BPF write. The flip just
    // refreshed this row in place and an in-place refresh never removes a row,
    // so `None` cannot follow a flip that applied; were it to, there would be
    // no row left in `SharedPromote` and nothing published.
    let Some(mut promoted_entry) = sessions.synced_entry_for(key) else {
        return (promoted, SyncedPromotion::FlipDeclined);
    };
    promoted_entry.decision = decision;
    promoted_entry.metadata = promoted.clone();
    promoted_entry.origin = SessionOrigin::SharedPromote;
    promoted_entry.protocol = protocol;
    promoted_entry.tcp_flags = tcp_flags;
    // #18552 (B1): flip F after R's entry is read, so no early return can
    // leave F flipped. The flip carries no TCP flags or ack: the packet belongs
    // to R, so F's TCP state is untouched (its last-seen is refreshed: a live
    // reply is evidence the flow is alive). F keeps its own stored decision and
    // metadata. A flip that does not apply leaves R promoted alone.
    let forward_partner = forward_partner.filter(|(forward_decision, forward_metadata, _)| {
        sessions.promote_synced_with_origin(SessionUpdate {
            key: &companion_key,
            decision: *forward_decision,
            metadata: forward_metadata.clone(),
            origin: SessionOrigin::SharedPromote,
            now_ns: shared.tick.ns,
            protocol: companion_key.protocol,
            tcp_flags: 0,
            ack: None,
        })
    });
    #[cfg(test)]
    run_promote_after_flip_hook();
    // The helper's promotion flips a peer-synced row to local ownership.
    // Clear only the origin bit in the conntrack mirror; counters,
    // timestamps, NAT state, and creation time remain untouched.
    // #18552: the `_under_permit` RMW, because the gated variant needs an
    // Idle tuple and would decline under this promotion's own permit.
    crate::afxdp::bpf_map::update_session_cluster_synced_origin_under_permit(
        shared.conntrack.v4,
        shared.conntrack.v6,
        key,
        false,
        &install_permits,
    );
    // #1789: count a failed shared-promote publish (shim would miss the
    // key -> NO_SESSION degraded path for the promoted flow).
    if publish_session_map_entry_for_session(
        session_map,
        key,
        decision,
        &promoted,
        forwarding.has_routing_domains,
        forwarding.has_multiple_zones,
    )
    .is_err()
    {
        crate::afxdp::bpf_map::SESSION_PUBLISH_ERRORS_SHARED
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    // #18552 (B1): the same legs for F: the origin bit (the permits fence F as
    // the pair's companion key) and its steering row.
    if let Some((forward_decision, forward_metadata, _)) = forward_partner.as_ref() {
        crate::afxdp::bpf_map::update_session_cluster_synced_origin_under_permit(
            shared.conntrack.v4,
            shared.conntrack.v6,
            &companion_key,
            false,
            &install_permits,
        );
        if publish_session_map_entry_for_session(
            session_map,
            &companion_key,
            *forward_decision,
            forward_metadata,
            forwarding.has_routing_domains,
            forwarding.has_multiple_zones,
        )
        .is_err()
        {
            crate::afxdp::bpf_map::SESSION_PUBLISH_ERRORS_SHARED
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    publish_shared_session(
        shared.sessions,
        shared.nat_sessions,
        shared.forward_wire_sessions,
        shared.owner_rg_indexes,
        &promoted_entry,
    );
    if let Some((_, _, forward_entry)) = forward_partner.as_ref() {
        publish_shared_session(
            shared.sessions,
            shared.nat_sessions,
            shared.forward_wire_sessions,
            shared.owner_rg_indexes,
            forward_entry,
        );
    }
    #[cfg(test)]
    run_promote_before_fanout_hook();
    replicate_session_upsert(shared.peer_worker_commands, shared.worker_commands_by_id, &promoted_entry);
    if let Some((_, _, forward_entry)) = forward_partner.as_ref() {
        replicate_session_upsert(
            shared.peer_worker_commands,
            shared.worker_commands_by_id,
            forward_entry,
        );
    }
    // #18552: released only after the shared publish and the fan-out.
    drop(install_permits);
    (promoted, SyncedPromotion::Promoted)
}

pub(in crate::afxdp) fn maybe_promote_synced_session(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    fabric_ingress: bool,
    protocol: u8,
    tcp_flags: u8,
    verdict: SessionHitVerdict,
) -> SessionMetadata {
    if verdict != SessionHitVerdict::Owner {
        return metadata;
    }
    // No-conntrack leg: force `-1, -1` so a caller that grafted real
    // fds onto the bundle cannot leak them into this entry point.
    let shared = shared.with_conntrack_tick(ConntrackFds { v4: -1, v6: -1 }, shared.tick);
    // No HA view on this test-only compatibility leg: no forward partner is
    // ever "ours", so a reverse hit promotes its companion alone, as before
    // #18552 (B1). Production enters through the `_with_conntrack` variant.
    let no_ha_view = BTreeMap::new();
    promote_synced_session_with_conntrack(
        sessions,
        session_map,
        shared,
        forwarding,
        &no_ha_view,
        key,
        decision,
        metadata,
        origin,
        fabric_ingress,
        protocol,
        tcp_flags,
        None,
    )
    .0
}
/// Evaluate the session-hit verdict before applying any deferred synced
/// materialization, purge, or promotion. Foreign and unresolved packets leave
/// the decision, metadata, shared maps, and local session state untouched.
pub(in crate::afxdp) fn maybe_promote_synced_session_with_conntrack(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    forwarding: &ForwardingState,
    // #18552 (B1): the HA view this packet's resolve and verdict used; it
    // decides whether a reverse hit's forward partner is locally owned.
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    tcp_flags: u8,
    worker_id: u32,
    verdict: SessionHitVerdict,
    resolved: &mut ResolvedFlowSessionDecision,
    evicted_keys: &mut Vec<SessionKey>,
) {
    if verdict != SessionHitVerdict::Owner {
        return;
    }
    apply_deferred_synced_purge(
        sessions,
        session_map,
        shared,
        forwarding,
        worker_id,
        verdict,
        resolved,
        evicted_keys,
    );

    super::apply_deferred_shared_materialization(
        sessions,
        shared.sessions,
        forwarding,
        shared.tick.ns,
        tcp_flags,
        verdict,
        resolved,
    );

    let Some(promotion) = resolved.deferred_synced_promotion.take() else {
        return;
    };
    // The deferred promotion carries its own install tick; graft it
    // so the promote leg stamps the install time, not the purge's.
    let shared = shared.with_conntrack_tick(
        shared.conntrack,
        Tick::from_ns(promotion.now_ns),
    );
    let (metadata, outcome) = promote_synced_session_with_conntrack(
        sessions,
        session_map,
        shared,
        forwarding,
        ha_state,
        &promotion.key,
        promotion.decision,
        promotion.metadata,
        promotion.origin,
        promotion.fabric_ingress,
        promotion.protocol,
        promotion.tcp_flags,
        promotion.ack,
    );
    resolved.metadata = metadata;
    // #18552 (review F1): the poll site keeps this packet out of the flow
    // cache, so a deferred promotion is retried by the next resolved hit.
    resolved.promotion_deferred = outcome.suppresses_flow_cache_seed();
    // #18552 cycle 2, rule (b): a diverged reconcile replaced the row this
    // packet resolved against. As for the #19153 materialize, the deferred
    // forwarding revalidation (derived from the replaced content) is dropped,
    // and a `Drop` divergence keeps the poll site from forwarding the packet.
    if let SyncedPromotion::ReconcileDiverged(divergence) = outcome {
        resolved.deferred_forwarding_revalidation = None;
        resolved.materialize_divergence = divergence;
    }
}


/// Purge a translated peer-synced hit: drop the entry from the shared
/// maps, delete the kernel session-map entry, remove the local session-table
/// entry, AND return the source-NAT / NAT64 pool reservation this forward
/// session reserved at install. Used when the local node is not the active
/// owner of a translated forward session — leaving the hit live would route
/// traffic to the wrong node.
///
/// #5295: the purged entry is a peer-synced FORWARD translated session
/// (the guard below rejects reverse/non-translated keys), so at install
/// `handle_upsert_synced` reserved its translated `(pool_addr, port)` in
/// THIS node's local allocator via `reserve_synced_source_nat_allocation`
/// / `reserve_synced_nat64_allocation`. Tearing the session down without
/// the matching release LEAKED that reservation — every alias-owned
/// transient purge burned a pool port, exhausting the standby's source-NAT
/// / NAT64 pool under sustained HA churn. Mirror the `handle_delete_synced`
/// (and `delete_terminal_filtered_session`) teardown: release under the
/// same `metadata.is_reverse` ownership guard so a reverse/alias entry (or
/// a non-pool / non-reserved session) frees nothing and a double-free is
/// impossible — `release_flow` is a no-op when the flow was never tracked.
///
/// #13674 (D11-08): this purge also owns the remaining teardown legs its
/// sibling purges (`purge_one_install_table_key`) run. It must (a) delete
/// the BPF conntrack mirror — the plain
/// `delete_session_map_entry_for_removed_session` hardcodes `-1,-1`
/// conntrack fds, leaving a stale kernel row the next packet would hit;
/// (b) fan `DeleteSynced` to sibling workers only if the shared session
/// captured by the lookup still has the same identity, so a replacement
/// under the key cannot be revoked by this stale hit; and (c) push the key
/// into `evicted_keys` so the worker invalidates flow-cache slots on every
/// binding. Sibling workers evict through their delete-sync teardown.
///
/// `key` identifies the stored session and is the tuple tested by the
/// translated-forward guard. `forwarding`, `now_ns`, and `worker_id` scope
/// the local NAT reservation release.
#[expect(clippy::too_many_arguments, reason = "#17200: wide dataplane signature; census in docs/log/17200.md")]
pub(in crate::afxdp::session_glue) fn purge_translated_synced_hit_with_context(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    shared_identity: Option<(u64, u64)>,
    forwarding: &ForwardingState,
    // #6211 F2: THIS worker's id. This purge tears down a PEER-SYNCED forward
    // session, whose reservation every worker holds, so it must drop only this
    // worker's bit.
    worker_id: u32,
    evicted_keys: &mut Vec<SessionKey>,
) -> bool {
    if !origin.is_peer_synced() || !is_translated_forward_session_key(key, decision, metadata) {
        return false;
    }
    let removed = if let Some((shared_session_id, generation)) = shared_identity {
        remove_shared_session_if(
            shared.sessions,
            shared.nat_sessions,
            shared.forward_wire_sessions,
            shared.owner_rg_indexes,
            key,
            |entry| entry.session_id == shared_session_id && entry.generation == generation,
        )
    } else {
        SharedRemoval::Absent
    };
    let session_id = sessions.session_id_for(key);
    let delete_result =
        delete_session_map_entry_for_removed_session_with_origin_and_id(
            session_map,
            key,
            decision,
            metadata,
            origin,
            shared.conntrack.v4,
            shared.conntrack.v6,
            session_id,
        );
    if delete_result == crate::afxdp::bpf_map::ConntrackDeleteResult::GateBusy {
        sessions.defer_conntrack_delete(crate::session::DeferredConntrackDelete {
            key: key.clone(),
            session_id,
        });
    }
    let persistent_hold_16615 = sessions.take_persistent_lease_hold(key);
    sessions.delete(key);
    evicted_keys.push(key.clone());
    if let (SharedRemoval::Removed(_), Some((session_id, _))) = (removed, shared_identity) {
        replicate_session_delete_conditional(
            shared.peer_worker_commands,
            shared.worker_commands_by_id,
            forwarding,
            key,
            decision.nat,
            metadata.is_reverse,
            shared.tick.ns,
            session_id,
            None,
            0,
        );
    }
    // #5295: return the pool reservation to the local allocator, exactly as
    // `handle_delete_synced` does on the delete-sync teardown. `is_reverse` is
    // the ownership guard (a reverse entry owns no source-NAT/NAT64 reservation);
    // both calls are a no-op for a non-pool / non-reserved session.
    crate::nat::release_source_nat_allocation_for_worker_with_hold(
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        key,
        decision.nat,
        metadata.is_reverse,
        shared.tick.ns,
        worker_id,
        persistent_hold_16615,
    );
    crate::nat64::release_nat64_allocation_for_worker(
        &forwarding.nat64,
        key,
        decision.nat,
        metadata.is_reverse,
        shared.tick.ns,
        worker_id,
    );
    true
}
/// Backwards-compatible internal wrapper for tests and callers that have no
/// conntrack fds, sibling command queues, or flow-cache invalidation owner.
#[cfg(test)]
pub(in crate::afxdp::session_glue) fn purge_translated_synced_hit(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    forwarding: &ForwardingState,
    worker_id: u32,
) {
    let mut evicted_keys = Vec::new();
    purge_translated_synced_hit_with_context(
        sessions,
        session_map,
        shared,
        key,
        decision,
        metadata,
        origin,
        None,
        forwarding,
        worker_id,
        &mut evicted_keys,
    );
}
fn apply_deferred_synced_purge(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared: SharedSessionRefs<'_>,
    forwarding: &ForwardingState,
    worker_id: u32,
    verdict: SessionHitVerdict,
    resolved: &mut ResolvedFlowSessionDecision,
    evicted_keys: &mut Vec<SessionKey>,
) {
    if verdict != SessionHitVerdict::Owner {
        return;
    }
    let Some(purge) = resolved.deferred_synced_purge.take() else {
        return;
    };
    purge_translated_synced_hit_with_context(
        sessions,
        session_map,
        shared,
        &purge.key,
        purge.decision,
        &purge.metadata,
        purge.origin,
        purge.shared_identity,
        forwarding,
        worker_id,
        evicted_keys,
    );
}
