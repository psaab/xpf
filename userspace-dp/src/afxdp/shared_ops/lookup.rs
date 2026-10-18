use super::*;

pub(in crate::afxdp) fn lookup_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    // #2402: recover poison so a prior worker panic does not turn every
    // shared-session lookup into a spurious miss.
    lock_shared_recover(shared_sessions).get(key).cloned()
}

#[derive(Clone, Copy)]
enum ReverseDomainAdmission {
    ForwardEgress,
    QuotedTupleOnly,
}

pub(in crate::afxdp) fn lookup_shared_forward_nat_match(
    forwarding: &ForwardingState,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    reply_key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    lookup_shared_forward_nat_match_with_admission(
        forwarding,
        shared_nat_sessions,
        Some(shared_owner_rg_indexes),
        reply_key,
        ReverseDomainAdmission::ForwardEgress,
    )
}

fn lookup_shared_forward_nat_match_with_admission(
    forwarding: &ForwardingState,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: Option<&SharedSessionOwnerRgIndexes>,
    reply_key: &SessionKey,
    domain_admission: ReverseDomainAdmission,
) -> Option<SyncedSessionEntry> {
    let matches_reply_domain = |entry: &SyncedSessionEntry, exact: bool| {
        let forward_key_domain = entry.key.routing_domain;
        if crate::session::is_quarantined_routing_domain(reply_key.routing_domain)
            || crate::session::is_quarantined_routing_domain(forward_key_domain)
        {
            return exact && forward_key_domain == reply_key.routing_domain;
        }
        match domain_admission {
            ReverseDomainAdmission::ForwardEgress => {
                crate::afxdp::forwarding::egress_routing_domain(
                    forwarding,
                    entry.decision.resolution.egress_ifindex,
                ) == reply_key.routing_domain
            }
            ReverseDomainAdmission::QuotedTupleOnly => true,
        }
    };

    // Domain-zero keys are canonical aliases, not owner identities. Even an
    // exact key hit needs a unique-owner proof before it can select a tenant.
    // The same holds in a nonzero domain (#14384): the shared map is keyed by
    // the domain-preserving reverse tuple, so two forward owners in that
    // domain DNATing to one backend publish the same key and the second
    // displaces the first. The publish path records that collision in the
    // ambiguity index under the domain-neutral probe, so the exact branch
    // must consult it instead of trusting the surviving slot.
    let exact = {
        let map = lock_shared_recover(shared_nat_sessions);
        map.get(reply_key).cloned()
    };
    if let Some(exact) = exact {
        if matches_reply_domain(&exact, true)
            && shared_owner_rg_indexes.is_some_and(|indexes| {
                if reply_key.routing_domain != 0 {
                    lock_shared_recover(&indexes.nat_ambiguities)
                        .is_unique_for(&crate::session::reverse_match_key(reply_key), &exact.key)
                } else {
                    shared_forward_nat_candidate_is_unique(
                        shared_nat_sessions,
                        indexes,
                        reply_key,
                        &exact.key,
                        exact.decision.nat,
                    )
                }
            })
        {
            return Some(exact);
        }
    }

    // A nonzero PRE-NAT reply can hit the domain-zero canonical alias directly.
    // Its candidate still needs a unique translated-wire owner and no conflicting
    // owner history for the canonical tuple.
    let probe = crate::session::reverse_match_key(reply_key);
    let indexes = shared_owner_rg_indexes?;
    if reply_key.routing_domain != 0 {
        let canonical_candidate = {
            let map = lock_shared_recover(shared_nat_sessions);
            map.get(&probe).cloned()
        };
        if let Some(candidate) = canonical_candidate {
            if reverse_canonical_key(&candidate.key, candidate.decision.nat) == probe {
                if candidate.metadata.is_reverse
                    || !shared_forward_nat_candidate_is_unique(
                        shared_nat_sessions,
                        indexes,
                        &probe,
                        &candidate.key,
                        candidate.decision.nat,
                    )
                {
                    return None;
                }
                return matches_reply_domain(&candidate, false).then_some(candidate);
            }
        }
    }
    let owner = lock_shared_recover(&indexes.nat_ambiguities)
        .unique_owner(&probe)
        .cloned()?;
    if crate::session::is_quarantined_routing_domain(owner.routing_domain) {
        return None;
    }
    let domain_stamped_probe = probe == *reply_key;
    if domain_stamped_probe && owner.routing_domain == 0 {
        return None;
    }
    let mut lookup_key = probe.clone();
    lookup_key.routing_domain = owner.routing_domain;
    let candidate = {
        let map = lock_shared_recover(shared_nat_sessions);
        map.get(&lookup_key).cloned()?
    };
    let wire_key = crate::session::reverse_session_key(&candidate.key, candidate.decision.nat);
    if candidate.metadata.is_reverse || candidate.key != owner || wire_key != lookup_key {
        return None;
    }
    if !shared_forward_nat_candidate_is_unique(
        shared_nat_sessions,
        indexes,
        &probe,
        &candidate.key,
        candidate.decision.nat,
    ) {
        return None;
    }
    matches_reply_domain(&candidate, false).then_some(candidate)
}

/// Prove that the shared reverse index contains the expected forward entry
/// and its domain-neutral translated tuple has only ever named that owner.
/// A canonical alias also fails closed on displacement or a different wire
/// owner for the same tuple. Saturation or any collision fails closed.
pub(in crate::afxdp) fn shared_forward_nat_candidate_is_unique(
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    reply_key: &SessionKey,
    expected_forward_key: &SessionKey,
    expected_nat: crate::nat::NatDecision,
) -> bool {
    if reply_key.routing_domain != 0 {
        return false;
    }
    let expected_alias = reverse_session_key(expected_forward_key, expected_nat);
    let canonical_alias = reverse_canonical_key(expected_forward_key, expected_nat);
    let probe = crate::session::reverse_match_key(reply_key);
    let wire_probe = crate::session::reverse_match_key(&expected_alias);
    let canonical_probe = crate::session::reverse_match_key(&canonical_alias);
    if probe != wire_probe && probe != canonical_probe {
        return false;
    }
    let unique_alias = {
        let map = lock_shared_recover(shared_nat_sessions);
        let Some(entry) = map.get(&expected_alias) else {
            return false;
        };
        !entry.metadata.is_reverse
            && entry.key == *expected_forward_key
            && entry.decision.nat == expected_nat
    };
    if !unique_alias {
        return false;
    }
    // Keep map and ambiguity locks unnested: publishers hold the ambiguity
    // lock while they publish aliases so readers cannot observe an alias
    // before its owner has been recorded.
    let ambiguities = lock_shared_recover(&shared_owner_rg_indexes.nat_ambiguities);
    ambiguities.is_unique_for(&wire_probe, expected_forward_key)
        && (probe == wire_probe
            || (!ambiguities.contains(&probe)
                && ambiguities
                    .unique_owner(&probe)
                    .map_or(true, |owner| owner == expected_forward_key)))
}

/// #14383: shared forward-wire lookup. The wire map holds ONE entry per
/// wire key over a displacing publish, so a bare map get resolved a
/// colliding tuple to the LAST-published session — the opposite tiebreak
/// from the local first-wins matcher. Fail closed unless the wire
/// ambiguity index proves this candidate is the key's only owner.
pub(in crate::afxdp) fn lookup_shared_forward_wire_match(
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    wire_key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    // #2402: recover poison (see lookup_shared_session).
    // Keep map and ambiguity locks unnested (mirrors
    // `shared_forward_nat_candidate_is_unique`): the map guard drops
    // before the ambiguity lock is taken.
    let candidate = lock_shared_recover(shared_forward_wire_sessions)
        .get(wire_key)
        .cloned()?;
    let ambiguities = lock_shared_recover(&shared_owner_rg_indexes.wire_ambiguities);
    if !ambiguities.is_unique_for(wire_key, &candidate.key) {
        return None;
    }
    Some(candidate)
}

/// Recover the canonical tuple for a translated transient alias only when the
/// shared forward-wire candidate carries the same nonzero session identity.
/// The index stores one candidate per wire key, so a wire-tuple collision must
/// not borrow another flow's original source selectors.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn shared_source_nat_original_key(
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    wire_key: &SessionKey,
    alias_key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    source_nat_static: Option<bool>,
    session_id: u64,
) -> Option<SessionKey> {
    if !origin.is_peer_synced()
        || metadata.is_reverse
        || (wire_key != alias_key && forward_wire_key(alias_key, decision.nat) != *wire_key)
        || session_id == 0
        || decision.nat.rewrite_src != Some(wire_key.src_ip)
    {
        return None;
    }

    let sessions = lock_shared_recover(shared_forward_wire_sessions);
    let original = sessions.get(wire_key)?;
    if original.session_id == 0
        || original.session_id != session_id
        || !original.origin.is_peer_synced()
        || original.metadata.is_reverse
        // UpsertSynced re-resolves forwarding on each worker. The local
        // egress and derived owner RG may legitimately differ from the
        // shared row; the policy scope and ingress identity below may not.
        || original.metadata.ingress_zone != metadata.ingress_zone
        || original.metadata.egress_zone != metadata.egress_zone
        || original.metadata.ingress_ifindex != metadata.ingress_ifindex
        || original.metadata.ingress_vlan_id != metadata.ingress_vlan_id
        || original.metadata.fabric_ingress != metadata.fabric_ingress
        || original.source_nat_static != source_nat_static
        || original.decision.nat != decision.nat
        || original.key == *wire_key
        || forward_wire_key(&original.key, original.decision.nat) != *wire_key
    {
        return None;
    }
    Some(original.key.clone())
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) enum ResolvedSessionKey {
    QueryKey,
    Canonical(SessionKey),
}

impl ResolvedSessionKey {
    pub(in crate::afxdp) fn as_ref<'a>(&'a self, query_key: &'a SessionKey) -> &'a SessionKey {
        match self {
            Self::QueryKey => query_key,
            Self::Canonical(key) => key,
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ResolvedSessionLookup {
    pub(in crate::afxdp) key: ResolvedSessionKey,
    pub(in crate::afxdp) lookup: SessionLookup,
    pub(in crate::afxdp) shared_entry: Option<SyncedSessionEntry>,
    pub(in crate::afxdp) origin: SessionOrigin,
    /// #13938: this local hit lookup deferred every packet-state mutation
    /// until the #9519 authority verdict, not only TCP close state.
    pub(in crate::afxdp) authority_deferred: bool,
}

impl ResolvedSessionLookup {
    pub(in crate::afxdp) fn local_query(lookup: SessionLookup, origin: SessionOrigin) -> Self {
        Self {
            key: ResolvedSessionKey::QueryKey,
            lookup,
            shared_entry: None,
            origin,
            authority_deferred: true,
        }
    }

    pub(in crate::afxdp) fn local(
        key: SessionKey,
        lookup: SessionLookup,
        origin: SessionOrigin,
    ) -> Self {
        Self {
            key: ResolvedSessionKey::Canonical(key),
            lookup,
            shared_entry: None,
            origin,
            authority_deferred: true,
        }
    }

    pub(in crate::afxdp) fn shared(entry: SyncedSessionEntry) -> Self {
        let origin = entry.origin;
        Self {
            key: ResolvedSessionKey::Canonical(entry.key.clone()),
            lookup: SessionLookup {
                decision: entry.decision,
                metadata: entry.metadata.clone(),
                forwarding_generation: ForwardingGenerationStamp::default(),
                aux: SessionLookupAux {
                    session_id: entry.session_id,
                    source_nat_static: entry.source_nat_static,
                    leak_incarnation: entry.leak_incarnation,
                },
            },
            shared_entry: Some(entry),
            origin,
            authority_deferred: false,
        }
    }
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ResolvedFlowSessionDecision {
    pub(in crate::afxdp) key: SessionKey,
    pub(in crate::afxdp) session_id: u64,
    /// #13079: in-force timeout window from the same installed entry.
    pub(in crate::afxdp) timeout_secs: u32,
    pub(in crate::afxdp) decision: SessionDecision,
    /// Ordinary source-NAT provenance from the installed or synced entry.
    /// `None` preserves conservative, revocable behavior for legacy rows.
    pub(in crate::afxdp) source_nat_static: Option<bool>,
    pub(in crate::afxdp) metadata: SessionMetadata,
    pub(in crate::afxdp) origin: SessionOrigin,
    /// Original forward tuple for a translated peer-synced transient hit.
    /// It is populated only when the shared alias and canonical row carry
    /// the same nonzero session identity and SNAT provenance.
    pub(in crate::afxdp) source_nat_validation_key: Option<SessionKey>,
    pub(in crate::afxdp) created: bool,
    /// #1861 §5.4: true when a session install was ATTEMPTED for this
    /// decision and refused (max_sessions) — distinct from "no install
    /// required" (hit paths, DNS fast-path), which stays false. The
    /// flow-cache population gate keys off this so a sessionless
    /// decision is never cached (caching it would suppress the
    /// per-packet reply repair until cache invalidation; Codex #1861
    /// r1 C1).
    pub(in crate::afxdp) install_failed: bool,
    /// The local packet hit lookup deferred session mutation until the #9519
    /// authority verdict; shared entries do not defer a local mutation.
    pub(in crate::afxdp) authority_deferred: bool,
    /// #13938: carried through from [`ResolvedSessionLookup::authority_deferred`].
    /// The poll site replays the complete hit mutation only after an Owner
    /// verdict (`apply_deferred_owner_hit`).
    /// #12265: a stale-generation forwarding re-resolve computed during
    /// `resolve`, NOT yet persisted. The poll site persists it after an Owner
    /// authority verdict (`revalidate_forwarding_resolution`) and drops it
    /// with a foreign arrival — mirroring the #10636 close deferral. It is
    /// persisted before that deferred close, so a #9412 close Update carries
    /// the refreshed route. `None` when the cached resolution was fresh or no
    /// persist is owed.
    pub(in crate::afxdp) deferred_forwarding_revalidation: Option<DeferredForwardingRevalidation>,
    /// #12644: promotion writes held until the #9519 Owner verdict.
    pub(in crate::afxdp) deferred_synced_promotion: Option<DeferredSyncedPromotion>,
    /// #12644: shared-map materialization held until an Owner verdict.
    pub(in crate::afxdp) deferred_shared_materialization: Option<DeferredSharedMaterialization>,
    /// #12644: transient-hit teardown held until an Owner verdict.
    pub(in crate::afxdp) deferred_synced_purge: Option<DeferredSyncedPurge>,
}

/// #12644: materialization of a shared hit held until the packet's authority
/// verdict, so a foreign packet cannot install peer state into the worker.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct DeferredSharedMaterialization {
    pub(in crate::afxdp) entry: SyncedSessionEntry,
}

#[derive(Clone, Debug)]
pub(in crate::afxdp) struct DeferredSyncedPurge {
    pub(in crate::afxdp) key: SessionKey,
    pub(in crate::afxdp) decision: SessionDecision,
    pub(in crate::afxdp) metadata: SessionMetadata,
    pub(in crate::afxdp) origin: SessionOrigin,
    pub(in crate::afxdp) shared_identity: Option<(u64, u64)>,
}

/// #12265: the #11373 re-resolve a stale hit computed, held for the #9519
/// authority verdict. Persisting inside `resolve` lets a denied foreign
/// packet rewrite the owner's resolution, stamp, and `owner_rg_id`, or
/// invalidate the owner's policy verdict.
#[derive(Clone, Copy, Debug)]
pub(in crate::afxdp) struct DeferredForwardingRevalidation {
    pub(in crate::afxdp) resolution: ForwardingResolution,
    pub(in crate::afxdp) owner_rg_id: Option<i32>,
    /// #12074: the re-resolve moved the policy to-zone, so the owner's
    /// cached policy verdict must be re-judged. Applied with the route, only
    /// after an Owner verdict (`invalidate_policy_revalidation`).
    pub(in crate::afxdp) invalidate_policy_revalidation: bool,
    /// #14318: the re-resolved route's policy egress zone, when it names a
    /// real flow egress (locally-forwarding, or the recorded zone for a
    /// fabric redirect). `None` for terminal/non-forwarding resolutions.
    /// Persisted with the route so the forward entry's `egress_zone` and
    /// the reverse companion's `ingress_zone` move with the reroute.
    pub(in crate::afxdp) new_egress_zone: Option<u16>,
}

/// #12644: a synced-session promotion computed during `resolve`, NOT yet
/// persisted. Mirrors the #12265 deferred revalidation: the poll site
/// applies it only after a #9519 Owner verdict and drops it with a foreign
/// arrival. Persisting inside `resolve` lets a denied foreign packet
/// re-home the owner's session (decision/owner_rg_id/fabric_ingress),
/// republish it to shared/BPF/peer, and replicate it. Carries everything
/// the Owner site needs to replay the promotion without recomputing.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct DeferredSyncedPromotion {
    pub(in crate::afxdp) key: SessionKey,
    pub(in crate::afxdp) decision: SessionDecision,
    pub(in crate::afxdp) metadata: SessionMetadata,
    pub(in crate::afxdp) origin: SessionOrigin,
    pub(in crate::afxdp) now_ns: u64,
    pub(in crate::afxdp) fabric_ingress: bool,
    pub(in crate::afxdp) protocol: u8,
    pub(in crate::afxdp) tcp_flags: u8,
}

// Fabric-ingress SNAT-only forward entries are standby-side wire placeholders
// in the split-RG topology: they should not win lookups over the real shared
// session and should not synthesize a competing local reverse session.
pub(in crate::afxdp) fn is_fabric_wire_placeholder(
    fabric_ingress: bool,
    is_reverse: bool,
    decision: SessionDecision,
) -> bool {
    fabric_ingress
        && !is_reverse
        && decision.nat.rewrite_src.is_some()
        && decision.nat.rewrite_dst.is_none()
}

/// Local expiry classification used before considering shared aliases. A stale
/// local record is terminal for this worker: its shared replica must not
/// resurrect a packet or quote that the local age gate rejected.
enum LocalExpiryProbe<T> {
    Live(T),
    Stale,
    Absent,
}

fn probe_local_exact_at(
    sessions: &SessionTable,
    key: &SessionKey,
    now_ns: u64,
) -> LocalExpiryProbe<(SessionLookup, SessionOrigin)> {
    match sessions.probe_with_origin_expiry(key, now_ns) {
        crate::session::SessionExpiryProbe::Live(hit) => LocalExpiryProbe::Live(hit),
        crate::session::SessionExpiryProbe::IdleCrossed => LocalExpiryProbe::Stale,
        crate::session::SessionExpiryProbe::Absent => LocalExpiryProbe::Absent,
    }
}

fn probe_local_wire_at(
    sessions: &SessionTable,
    key: &SessionKey,
    now_ns: u64,
) -> LocalExpiryProbe<(ForwardSessionMatch, SessionOrigin)> {
    match sessions.find_forward_wire_match_expiry(key, now_ns) {
        crate::session::SessionExpiryProbe::Live(hit) => LocalExpiryProbe::Live(hit),
        crate::session::SessionExpiryProbe::IdleCrossed => LocalExpiryProbe::Stale,
        crate::session::SessionExpiryProbe::Absent => LocalExpiryProbe::Absent,
    }
}

fn retire_shared_tcp_pair_for_syn(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) {
    let _ = remove_shared_session_if(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        forward_key,
        |entry| entry.tcp_close_class != 0,
    );
    if reverse_key != forward_key {
        let _ = remove_shared_session_if(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            reverse_key,
            |entry| entry.tcp_close_class != 0,
        );
    }
}

fn shared_closing_tcp_entry_for_syn(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    tcp_flags: u8,
) -> Option<(SessionKey, SessionKey)> {
    if !crate::tcp_flags::is_initial_syn(tcp_flags) || crate::tcp_flags::is_closing(tcp_flags) {
        return None;
    }
    let entry = lookup_shared_session(shared_sessions, key).or_else(|| {
        lookup_shared_forward_wire_match(shared_forward_wire_sessions, shared_owner_rg_indexes, key)
    })?;
    if entry.tcp_close_class == 0 {
        return None;
    }
    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    if entry.metadata.is_reverse {
        Some((reverse_key, entry.key))
    } else {
        Some((entry.key, reverse_key))
    }
}

/// Reject a malformed TCP packet before session lookup can refresh or mutate a
/// hit. Established traffic needs ACK; SYN-bearing segments (including SYN+PSH)
/// and FIN/RST teardown packets retain their normal hit path. This is a
/// flag-contract guard, not one of the opt-in stateless TCP-flag screens.
///
/// Probe only for the ACK-less, non-SYN, non-closing case. The normal session
/// miss gate handles a miss; a live local or shared hit is dropped here so it
/// cannot refresh, complete a handshake, or proceed as a miss and replace the
/// established state.
pub(in crate::afxdp) fn should_drop_tcp_session_hit_for_flags(
    sessions: &SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
    now_ns: u64,
    tcp_flags: u8,
) -> bool {
    if !matches!(key.protocol, PROTO_TCP)
        || crate::tcp_flags::has_syn(tcp_flags)
        || crate::tcp_flags::has_ack(tcp_flags)
        || crate::tcp_flags::is_closing(tcp_flags)
    {
        return false;
    }

    sessions.has_session_hit_at(key, now_ns)
        || lock_shared_recover(shared_sessions).contains_key(key)
        || lock_shared_recover(shared_forward_wire_sessions).contains_key(key)
}

/// A live closing pair matched by a bare SYN. This is only a probe: the poll
/// path checks packet authority before deciding whether to miss the session,
/// and evicts only after owner policy and replacement admission both succeed.
#[derive(Clone, Debug)]
pub(in crate::afxdp) struct ClosingSynCandidate {
    pub(in crate::afxdp) key: SessionKey,
    pub(in crate::afxdp) metadata: SessionMetadata,
    pub(in crate::afxdp) origin: SessionOrigin,
}

pub(in crate::afxdp) fn probe_closing_syn_candidate(
    sessions: &SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    now_ns: u64,
    tcp_flags: u8,
) -> Option<ClosingSynCandidate> {
    if !matches!(key.protocol, crate::ip_proto::PROTO_TCP)
        || !crate::tcp_flags::is_initial_syn(tcp_flags)
        || crate::tcp_flags::is_closing(tcp_flags)
    {
        return None;
    }
    let hit = probe_session_across_scopes(
        sessions,
        shared_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        key,
        now_ns,
    )?;
    let canonical_key = hit.key.as_ref(key).clone();
    let closing = hit
        .shared_entry
        .as_ref()
        .is_some_and(|entry| entry.tcp_close_class != 0)
        || (hit.shared_entry.is_none()
            && sessions.is_closing_tcp_pair_for_syn(&canonical_key, tcp_flags));
    closing.then(|| ClosingSynCandidate {
        key: canonical_key,
        metadata: hit.lookup.metadata,
        origin: hit.origin,
    })
}

/// Retire an old closing incarnation after the owner's new-flow policy and
/// applicable capacity/tuple admission gates accept its SYN. A foreign SYN
/// never calls this; ordinary lookups remain read/refresh-only and cannot
/// evict either local or shared copies.
pub(in crate::afxdp) fn evict_owner_closing_tcp_pair_for_syn(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    tcp_flags: u8,
) -> bool {
    let pair = sessions
        .evict_closing_tcp_pair_for_syn(key, tcp_flags)
        .or_else(|| {
            shared_closing_tcp_entry_for_syn(
                shared_sessions,
                shared_forward_wire_sessions,
                shared_owner_rg_indexes,
                key,
                tcp_flags,
            )
        });
    let Some((forward_key, reverse_key)) = pair else {
        return false;
    };
    retire_shared_tcp_pair_for_syn(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        &forward_key,
        &reverse_key,
    );
    true
}

pub(in crate::afxdp) fn lookup_session_across_scopes_with_shared(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    _shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    now_ns: u64,
    tcp_flags: u8,
) -> Option<ResolvedSessionLookup> {
    lookup_session_across_scopes_with_shared_and_payload(
        sessions,
        shared_sessions,
        _shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        key,
        now_ns,
        tcp_flags,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn lookup_session_across_scopes_with_shared_and_payload(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    _shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    now_ns: u64,
    tcp_flags: u8,
    payload_len: u32,
) -> Option<ResolvedSessionLookup> {
    if !crate::session::PMechSessionDirectory::global()
        .probe_packet_key(key)
        .is_fallthrough()
    {
        return None;
    }
    match sessions.lookup_with_origin_deferring_authority_with_payload(key, now_ns, tcp_flags, payload_len) {
        crate::session::SessionExpiryProbe::Live((lookup, origin)) => {
            if is_fabric_wire_placeholder(
                lookup.metadata.fabric_ingress,
                lookup.metadata.is_reverse,
                lookup.decision,
            ) && let Some(shared) =
                lookup_shared_forward_wire_match(shared_forward_wire_sessions, shared_owner_rg_indexes, key)
            {
                return Some(ResolvedSessionLookup::shared(shared));
            }
            return Some(ResolvedSessionLookup::local_query(lookup, origin));
        }
        crate::session::SessionExpiryProbe::IdleCrossed => return None,
        crate::session::SessionExpiryProbe::Absent => {}
    }
    match probe_local_wire_at(sessions, key, now_ns) {
        LocalExpiryProbe::Live((matched, origin)) => {
            let lookup = SessionLookup {
                decision: matched.decision,
                metadata: matched.metadata,
                forwarding_generation: matched.forwarding_generation,
                aux: matched.aux,
            };
            if is_fabric_wire_placeholder(
                lookup.metadata.fabric_ingress,
                lookup.metadata.is_reverse,
                lookup.decision,
            ) && let Some(shared) =
                lookup_shared_forward_wire_match(shared_forward_wire_sessions, shared_owner_rg_indexes, key)
            {
                return Some(ResolvedSessionLookup::shared(shared));
            }
            return Some(ResolvedSessionLookup::local(matched.key, lookup, origin));
        }
        LocalExpiryProbe::Stale => return None,
        LocalExpiryProbe::Absent => {}
    }
    lookup_shared_session(shared_sessions, key)
        .map(ResolvedSessionLookup::shared)
        .or_else(|| {
            lookup_shared_forward_wire_match(shared_forward_wire_sessions, shared_owner_rg_indexes, key)
                .map(ResolvedSessionLookup::shared)
        })
}

#[cfg(test)]
pub(in crate::afxdp) fn lookup_session_across_scopes_for_test(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
    now_ns: u64,
    tcp_flags: u8,
) -> Option<ResolvedSessionLookup> {
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    lookup_session_across_scopes_with_shared(
        sessions,
        shared_sessions,
        &shared_nat_sessions,
        shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        key,
        now_ns,
        tcp_flags,
    )
}

/// #14383: like [`lookup_session_across_scopes_for_test`] but against the
/// caller's own owner-RG indexes, so a fixture that published through
/// `publish_shared_session` is looked up against the same wire ambiguity
/// index the publish recorded into.
#[cfg(test)]
pub(in crate::afxdp) fn lookup_session_across_scopes_for_test_with_indexes(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    now_ns: u64,
    tcp_flags: u8,
) -> Option<ResolvedSessionLookup> {
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    lookup_session_across_scopes_with_shared(
        sessions,
        shared_sessions,
        &shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        key,
        now_ns,
        tcp_flags,
    )
}

/// #9990: non-mutating counterpart to [`lookup_session_across_scopes_with_shared`].
///
/// Delete guards and embedded-error quote matching inspect an installed
/// decision before deciding whether to remove, rewrite, or account for it.
/// They must not run the packet-hit state machine (`last_seen_ns`,
/// handshake completion, companion propagation, or wheel refresh). Local
/// probes still honor the session's strict idle deadline; shared HA entries
/// retain their existing map-owned lifetime and are intentionally not aged by
/// this worker-local check.
pub(in crate::afxdp) fn probe_session_across_scopes(
    sessions: &SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    now_ns: u64,
) -> Option<ResolvedSessionLookup> {
    probe_session_across_scopes_with_wire_indexes(
        sessions,
        shared_sessions,
        shared_forward_wire_sessions,
        Some(shared_owner_rg_indexes),
        key,
        now_ns,
    )
}

/// #14383: probe variant for callers that may not carry the wire ambiguity
/// index (test-only ICMP constructors pass `None`). Without the index there
/// is no uniqueness proof, so the shared forward-wire fallback is skipped
/// rather than resolving a possibly-displaced entry.
pub(in crate::afxdp) fn probe_session_across_scopes_with_wire_indexes(
    sessions: &SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: Option<&SharedSessionOwnerRgIndexes>,
    key: &SessionKey,
    now_ns: u64,
) -> Option<ResolvedSessionLookup> {
    let wire_lookup = |key: &SessionKey| {
        shared_owner_rg_indexes.and_then(|indexes| {
            lookup_shared_forward_wire_match(shared_forward_wire_sessions, indexes, key)
        })
    };
    match probe_local_exact_at(sessions, key, now_ns) {
        LocalExpiryProbe::Live((lookup, origin)) => {
            if is_fabric_wire_placeholder(
                lookup.metadata.fabric_ingress,
                lookup.metadata.is_reverse,
                lookup.decision,
            ) && let Some(shared) = wire_lookup(key)
            {
                return Some(ResolvedSessionLookup::shared(shared));
            }
            return Some(ResolvedSessionLookup::local_query(lookup, origin));
        }
        LocalExpiryProbe::Stale => return None,
        LocalExpiryProbe::Absent => {}
    }
    match probe_local_wire_at(sessions, key, now_ns) {
        LocalExpiryProbe::Live((matched, origin)) => {
            let lookup = SessionLookup {
                decision: matched.decision,
                metadata: matched.metadata,
                forwarding_generation: matched.forwarding_generation,
                aux: matched.aux,
            };
            if is_fabric_wire_placeholder(
                lookup.metadata.fabric_ingress,
                lookup.metadata.is_reverse,
                lookup.decision,
            ) && let Some(shared) = wire_lookup(key)
            {
                return Some(ResolvedSessionLookup::shared(shared));
            }
            return Some(ResolvedSessionLookup::local(matched.key, lookup, origin));
        }
        LocalExpiryProbe::Stale => return None,
        LocalExpiryProbe::Absent => {}
    }
    lookup_shared_session(shared_sessions, key)
        .map(ResolvedSessionLookup::shared)
        .or_else(|| wire_lookup(key).map(ResolvedSessionLookup::shared))
}

/// #7169: what the caller knows about where the packet being matched actually
/// ARRIVED, so a reverse-canonical match can be revalidated against it.
///
/// The reverse-canonical index is keyed on a session's PRE-NAT reply tuple, so a
/// match means only "this 5-tuple equals a live session's private-side reply
/// tuple". Nothing about that establishes the packet came from where the reply
/// was expected — and on the main path a match installs a reverse session
/// carrying the original flow's zone pair, which then takes the established fast
/// path with no policy evaluation. Tuple equality alone was deciding both.
///
/// Three states, deliberately, with no variant that silently means "skip":
/// a lookup miss must not fail open into the same hole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum ReverseIngress {
    /// The zone the packet actually arrived in. A match is accepted only if the
    /// forward session EGRESSED to this zone — a reply must come back from
    /// where the flow went.
    ///
    /// Zone, not ifindex, on purpose: a zone can legitimately span interfaces,
    /// so a reply may arrive on a different member (LAG, ECMP, a route change)
    /// and still be the same flow. Ifindex equality would reject those. Zone is
    /// also the granularity policy is written against, which is what the
    /// synthesized session's metadata gets wrong.
    Zone(u16),
    /// The arrival interface has no zone mapping, so there is nothing to
    /// revalidate against. Fails CLOSED: no reverse match is synthesized.
    /// Distinct from `Unconstrained` precisely so an unmapped ifindex cannot
    /// reach the same outcome as a deliberate exemption.
    Unzoned,
    /// The caller has no arrival-zone constraint. Egress-domain admission
    /// still applies; embedded ICMP quotes use the separate tuple-only API.
    /// The active exemption is a FABRIC-ingress packet, which arrives on the
    /// fabric link from the peer node rather than in its logical ingress zone.
    Unconstrained,
}

/// Apply the #7169 ingress revalidation to a candidate match.
fn revalidate_reverse_ingress(
    m: ForwardSessionMatch,
    ingress: ReverseIngress,
) -> Option<ForwardSessionMatch> {
    match ingress {
        ReverseIngress::Unconstrained => Some(m),
        ReverseIngress::Unzoned => None,
        // The reply must arrive from the zone the forward flow egressed to.
        // On mismatch this returns NO MATCH rather than dropping: the packet
        // then falls through to ordinary policy evaluation IN THE ZONE IT
        // ACTUALLY ARRIVED IN, which is the correct adjudication. Dropping here
        // would substitute one unconsidered verdict for another.
        ReverseIngress::Zone(z) if m.metadata.egress_zone == z => Some(m),
        ReverseIngress::Zone(_) => None,
    }
}

pub(in crate::afxdp) fn lookup_forward_nat_across_scopes(
    sessions: &SessionTable,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    reply_key: &SessionKey,
    ingress: ReverseIngress,
) -> Option<ForwardSessionMatch> {
    let m = lookup_forward_nat_across_scopes_inner(
        sessions,
        shared_nat_sessions,
        forwarding,
        shared_owner_rg_indexes,
        reply_key,
        None,
        ReverseDomainAdmission::ForwardEgress,
    )?;
    revalidate_reverse_ingress(m, ingress)
}

pub(in crate::afxdp) fn lookup_forward_nat_across_scopes_at(
    sessions: &SessionTable,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    reply_key: &SessionKey,
    ingress: ReverseIngress,
    now_ns: u64,
) -> Option<ForwardSessionMatch> {
    let m = lookup_forward_nat_across_scopes_inner(
        sessions,
        shared_nat_sessions,
        forwarding,
        shared_owner_rg_indexes,
        reply_key,
        Some(now_ns),
        ReverseDomainAdmission::ForwardEgress,
    )?;
    revalidate_reverse_ingress(m, ingress)
}

/// Read-only reverse-tuple lookup for embedded ICMP quotes. Off-path routers
/// can send an error from a routing domain other than the forward egress, so
/// this path validates tuple identity (and the quarantine fence) without
/// applying reverse-session admission. Local and shared candidates fail closed
/// when multiple routing domains own the same translated tuple.
pub(in crate::afxdp) fn lookup_forward_nat_for_icmp_quote_at(
    sessions: &SessionTable,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: Option<&SharedSessionOwnerRgIndexes>,
    forwarding: &ForwardingState,
    reply_key: &SessionKey,
    now_ns: u64,
) -> Option<ForwardSessionMatch> {
    if !crate::session::PMechSessionDirectory::global()
        .probe_packet_key(reply_key)
        .is_fallthrough()
    {
        return None;
    }
    let local_match = match sessions.find_forward_nat_quote_match_at(reply_key, now_ns) {
        crate::session::ForwardNatQuoteLookup::NoMatch => None,
        crate::session::ForwardNatQuoteLookup::Unique(local) => Some(local),
        crate::session::ForwardNatQuoteLookup::Ambiguous => return None,
    };
    if local_match.is_none()
        && sessions
            .find_forward_nat_match(reply_key, |_| reply_key.routing_domain)
            .is_some()
    {
        // A wheel-lazy local entry was found but failed the strict age gate.
        // Do not resurrect its shared-map clone on this worker.
        return None;
    }
    let shared_match = lookup_shared_forward_nat_match_with_admission(
        forwarding,
        shared_nat_sessions,
        shared_owner_rg_indexes,
        reply_key,
        ReverseDomainAdmission::QuotedTupleOnly,
    )
    .map(|entry| ForwardSessionMatch {
        key: entry.key,
        decision: entry.decision,
        metadata: entry.metadata,
        forwarding_generation: ForwardingGenerationStamp::default(),
        aux: SessionLookupAux {
            session_id: entry.session_id,
            source_nat_static: entry.source_nat_static,
            leak_incarnation: entry.leak_incarnation,
        },
    });
    let shared_match = if let Some(shared) = shared_match {
        if !crate::session::is_quarantined_routing_domain(reply_key.routing_domain)
            && !crate::session::is_quarantined_routing_domain(shared.key.routing_domain)
        {
            let Some(indexes) = shared_owner_rg_indexes else {
                return None;
            };
            let mut canonical_reply_key = reply_key.clone();
            canonical_reply_key.routing_domain = 0;
            if !shared_forward_nat_candidate_is_unique(
                shared_nat_sessions,
                indexes,
                &canonical_reply_key,
                &shared.key,
                shared.decision.nat,
            ) {
                return None;
            }
        }
        Some(shared)
    } else {
        None
    };
    match (local_match, shared_match) {
        (Some(local), Some(shared)) => {
            if local.key.routing_domain != shared.key.routing_domain {
                return None;
            }
            if is_fabric_wire_placeholder(
                local.metadata.fabric_ingress,
                local.metadata.is_reverse,
                local.decision,
            ) {
                Some(shared)
            } else {
                Some(local)
            }
        }
        (Some(local), None) => Some(local),
        (None, Some(shared)) => Some(shared),
        (None, None) => None,
    }
}

fn lookup_forward_nat_across_scopes_inner(
    sessions: &SessionTable,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forwarding: &ForwardingState,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    reply_key: &SessionKey,
    now_ns: Option<u64>,
    domain_admission: ReverseDomainAdmission,
) -> Option<ForwardSessionMatch> {
    if !crate::session::PMechSessionDirectory::global()
        .probe_packet_key(reply_key)
        .is_fallthrough()
    {
        return None;
    }
    let egress_domain = |ifindex| match domain_admission {
        ReverseDomainAdmission::ForwardEgress => {
            crate::afxdp::forwarding::egress_routing_domain(forwarding, ifindex)
        }
        ReverseDomainAdmission::QuotedTupleOnly => reply_key.routing_domain,
    };
    let local_match = match now_ns {
        Some(now) => match sessions.find_forward_nat_match_expiry(reply_key, now, &egress_domain) {
            crate::session::ForwardNatExpiryProbe::Live(hit) => Some(hit),
            crate::session::ForwardNatExpiryProbe::IdleCrossed => {
                // Do not resurrect an expired local entry from its shared clone.
                return None;
            }
            crate::session::ForwardNatExpiryProbe::Absent => None,
        },
        None => sessions.find_forward_nat_match(reply_key, &egress_domain),
    };
    if let Some(local) = local_match {
        if is_fabric_wire_placeholder(
            local.metadata.fabric_ingress,
            local.metadata.is_reverse,
            local.decision,
        ) {
            return lookup_shared_forward_nat_match_with_admission(
                forwarding,
                shared_nat_sessions,
                Some(shared_owner_rg_indexes),
                reply_key,
                domain_admission,
            )
            .map(|entry| ForwardSessionMatch {
                key: entry.key,
                decision: entry.decision,
                metadata: entry.metadata,
                forwarding_generation: ForwardingGenerationStamp::default(),
                aux: SessionLookupAux {
                    session_id: entry.session_id,
                    source_nat_static: entry.source_nat_static,
                    leak_incarnation: entry.leak_incarnation,
                },
            });
        }
        return Some(local);
    }
    lookup_shared_forward_nat_match_with_admission(
        forwarding,
        shared_nat_sessions,
        Some(shared_owner_rg_indexes),
        reply_key,
        domain_admission,
    )
    .map(|entry| ForwardSessionMatch {
        key: entry.key,
        decision: entry.decision,
        metadata: entry.metadata,
        forwarding_generation: ForwardingGenerationStamp::default(),
        aux: SessionLookupAux {
            session_id: entry.session_id,
            source_nat_static: entry.source_nat_static,
            leak_incarnation: entry.leak_incarnation,
        },
    })
}
