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

/// #18552 (review F2): which incarnation the SHARED row for `key` names,
/// judged against THIS worker's row for `key`.
///
/// Identity is the RT_FLOW session id plus the NAT decision: the two fields
/// both the worker row and `SyncedSessionEntry` carry. The worker row does not
/// store the peer's install generation, and a same-incarnation resend bumps
/// the generation (the peer stamps every send from one climbing counter), so
/// generation is deliberately not compared: such a resend is still `Current`.
/// A new incarnation of a reused 5-tuple carries a different session id, and
/// a translation change a different NAT decision; either is `Superseded`.
///
/// A shared session id of 0 is the unknown/legacy sentinel (a peer that
/// predates the field). The worker never stores 0: it mints a node-local id
/// for such a row (`session/install.rs`), so the ids cannot match and only
/// the NAT decision is compared. The harm F2 guards against (a freed T1, a
/// late companion) needs a different translation, which that still catches.
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
        Some(entry)
            if entry.decision.nat != nat
                || (entry.session_id != 0 && entry.session_id != session_id) =>
        {
            SyncedRowIncarnation::Superseded
        }
        Some(entry) if !entry.origin.is_peer_synced() => SyncedRowIncarnation::SharedLocal,
        Some(_) => SyncedRowIncarnation::Current,
    }
}

/// #18552 (B1: Codex P1-4 = r24 P2-1(a), the lead's Option B): the forward
/// row F that a reverse-hit promotion of its companion R promotes with it,
/// under the same permit (which already claims `[R, F]`). Returns F's stored
/// decision and metadata and the shared entry to publish for it, read BEFORE
/// any flip. `None` means R is promoted alone:
///
/// - `key` is not a reverse companion: forward hits are unchanged, and a
///   forward hit never promotes its reverse;
/// - this worker holds no promotable-synced forward F under `forward_key`
///   whose own companion is `key`;
/// - F's owner RG is not locally active in `ha_state`, the HA view the hit's
///   own verdict used. In a split RG, F's owner (which holds the source-NAT
///   allocation) stays authoritative for the pair, so its imports and deletes
///   legitimately apply to F; an owner of 0 (unknown) is not "ours" either;
/// - shared authority does not name F's current incarnation
///   (`synced_row_incarnation`): F is being replaced or deleted, and its
///   queued worker command repairs it.
///
/// Why F at all: the #9678 import gate and the #9714 peer-delete guard read
/// only the FORWARD row. With R promoted alone, F stayed `SyncImport`, so a
/// late different-translation import of F passed #9678 and freed T1, and a
/// peer delete of F passed #9714 and took R with it.
fn reverse_hit_forward_partner(
    sessions: &SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    key: &SessionKey,
    metadata: &SessionMetadata,
    forward_key: &SessionKey,
) -> Option<(SessionDecision, SessionMetadata, SyncedSessionEntry)> {
    if !metadata.is_reverse {
        return None;
    }
    let (forward_decision, forward_metadata, forward_origin) =
        sessions.entry_with_origin(forward_key)?;
    if !forward_origin.is_promotable_synced()
        || forward_metadata.is_reverse
        || reverse_session_key(forward_key, forward_decision.nat) != *key
    {
        return None;
    }
    if !owner_rg_is_locally_active(ha_state, forward_metadata.owner_rg_id, now_secs) {
        return None;
    }
    if synced_row_incarnation(sessions, shared_sessions, forward_key)
        != SyncedRowIncarnation::Current
    {
        return None;
    }
    let mut forward_entry = sessions.synced_entry_for(forward_key)?;
    forward_entry.origin = SessionOrigin::SharedPromote;
    Some((forward_decision, forward_metadata, forward_entry))
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
    /// - The rest change nothing a later hit could retry.
    pub(in crate::afxdp) fn suppresses_flow_cache_seed(self) -> bool {
        matches!(
            self,
            Self::Deferred | Self::NotCurrent(SyncedRowIncarnation::Superseded)
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
    let incarnation = synced_row_incarnation(sessions, shared.sessions, key);
    if incarnation != SyncedRowIncarnation::Current {
        return (promoted, SyncedPromotion::NotCurrent(incarnation));
    }
    // #18552 (B1): a reverse hit promotes its forward F too, when F is ours
    // and current. Decided here, with every R check, before ANY flip; when F
    // does not qualify, R is promoted alone.
    let forward_partner = reverse_hit_forward_partner(
        sessions,
        shared.sessions,
        ha_state,
        shared.tick.secs,
        key,
        &promoted,
        &companion_key,
    );
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
