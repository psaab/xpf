use super::*;

/// #16217: INPUT evidence for the ct-slice collector and the export
/// stamp — reverse service observed for the canonical key anywhere
/// in the shared maps. Fail-closed: only an ACTUAL reverse packet
/// count > 0 read off a row counts (`SyncedSessionEntry::rev_packets`,
/// snapshotted from the serving forward entry's admitted reverse
/// counters at publish/restamp time). Mere existence of a synthesized
/// reverse companion NEVER counts — it is published with
/// `rev_packets = 0`. A shared row's Established WIRE is deliberately
/// NOT read here: shared Established is an OUTPUT of the restamp this
/// evidence feeds, so importing it would be chicken-and-egg. (The
/// import/GC consumers that may trust the wire use
/// `shared_node_served_evidence` instead.)
///
/// Scope (fold B2) + cost (fold B5): O(1) keyed gets only, full
/// `SessionKey` equality. The pre-fold full-map scan compared
/// `bare_tuple()`, so identical 5-tuples in another routing domain
/// (or another tunnel discriminator) leaked reverse counts into
/// this key's evidence — the adoption arm was scoped (Codex
/// cross-VRF) but the ct-slice promotion and bulk-export stamp
/// were not, so a cross-VRF sibling could promote/stamp a pending
/// row Established here. A row vouches when its stored key IS the
/// canonical key, the derived reverse companion, the forward-wire
/// alias, or the NAT'd reverse companion. A reverse row's
/// `rev_packets` IS this pair's reverse count by construction; a
/// forward row stored under the canonical (or wire-alias) key
/// carries the pair's counters too (snapshotted from the serving
/// forward entry).
///
/// Lock order: `shared_sessions` THEN `shared_forward_wire_sessions`
/// — the single node-wide order for the shared maps. Every function
/// that needs both maps takes them in this order and never holds
/// them in reverse; see `restamp_shared_forward_wire_established`.
fn shared_completion_evidence_for_maps(
    holders: &FastMap<SessionKey, SyncedSessionEntry>,
    wires: &FastMap<SessionKey, SyncedSessionEntry>,
    key: &SessionKey,
) -> crate::session::NodeServedEvidence {
    let mut ev = crate::session::NodeServedEvidence::default();
    let nat = holders
        .get(key)
        .or_else(|| wires.get(key))
        .map(|e| e.decision.nat)
        .unwrap_or_default();
    let reverse_key = crate::session::reverse_session_key(key, nat);
    let wire_key = crate::session::forward_wire_key(key, nat);
    let rev_wire_key = crate::session::forward_wire_key(&reverse_key, nat);
    for map in [holders, wires] {
        for k in [key, &reverse_key, &wire_key, &rev_wire_key] {
            if let Some(entry) = map.get(k)
                && entry.rev_packets > 0
                && (entry.metadata.is_reverse || *k == *key || *k == wire_key)
            {
                ev.rev_packets_any = ev.rev_packets_any.max(entry.rev_packets);
            }
        }
    }
    ev
}

/// Whether a live primary row still derives the exact, routing-scoped alias
/// being probed. Canonical reverse keys normally zero the domain for shared
/// reverse-match admission; evidence must restore the owner's scope.
fn shared_node_served_entry_claims_alias(
    entry: &SyncedSessionEntry,
    key: &SessionKey,
) -> bool {
    if entry.key.routing_domain != key.routing_domain {
        return false;
    }
    if entry.metadata.is_reverse {
        // A reverse NAT row derives both the canonical forward tuple and
        // its plain-reverse wire alias (used by an Opening promoted row).
        crate::session::reverse_session_key(&entry.key, entry.decision.nat) == *key
            || crate::session::reverse_session_key(
                &entry.key,
                crate::nat::NatDecision::default(),
            ) == *key
    } else {
        let mut canonical =
            crate::session::reverse_canonical_key(&entry.key, entry.decision.nat);
        canonical.routing_domain = entry.key.routing_domain;
        crate::session::reverse_session_key(&entry.key, entry.decision.nat) == *key
            || canonical == *key
    }
}

#[cfg(test)]
pub(in crate::afxdp) fn shared_completion_evidence(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) -> crate::session::NodeServedEvidence {
    // Both maps, canonical order (shared_sessions first), held
    // together so the two halves of the evidence are one snapshot.
    let holders = lock_shared_recover(shared_sessions);
    let wires = lock_shared_recover(shared_forward_wire_sessions);
    shared_completion_evidence_for_maps(&holders, &wires, key)
}

/// #18662: compute every pending worker row's evidence under one shared-map
/// lock pair per worker slice. Strict local completions are left untouched.
pub(in crate::afxdp) fn shared_completion_evidence_batch(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    candidates: &mut [crate::session::NodeServedForwardCandidate],
) {
    if !candidates.iter().any(|candidate| candidate.needs_shared) {
        return;
    }
    let holders = lock_shared_recover(shared_sessions);
    let wires = lock_shared_recover(shared_forward_wire_sessions);
    #[cfg(test)]
    {
        SHARED_COMPLETION_EVIDENCE_BATCH_LOCK_PAIRS_18662
            .with(|count| count.set(count.get() + 1));
        let pending_rows = candidates
            .iter()
            .filter(|candidate| candidate.needs_shared)
            .count() as u64;
        SHARED_COMPLETION_EVIDENCE_BATCH_PENDING_ROWS_18662
            .with(|count| count.set(count.get() + pending_rows));
    }
    for candidate in candidates.iter_mut().filter(|candidate| candidate.needs_shared) {
        candidate.shared = shared_completion_evidence_for_maps(&holders, &wires, &candidate.key);
    }
}

#[cfg(test)]
thread_local! {
    pub(in crate::afxdp) static SHARED_COMPLETION_EVIDENCE_BATCH_LOCK_PAIRS_18662: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
    pub(in crate::afxdp) static SHARED_COMPLETION_EVIDENCE_BATCH_PENDING_ROWS_18662: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

/// #16223: node-level served-handshake evidence for `key` (either half of
/// the pair), with #18722/#18742's counts, incarnation and recency proof.
/// #18663: every branch is a keyed primary or alias lookup. Direct and plain
/// reverse keys retain precedence; translated aliases resolve through the
/// live alias-owner index maintained with `shared_sessions` under the same
/// lock. Alias collisions fail closed, and the resolved primary is checked
/// again while that lock remains held.
pub(in crate::afxdp) fn shared_node_served_evidence(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
) -> crate::session::NodeServedEvidence {
    let established = crate::session::TcpHandshakeState::Established.to_wire();
    let mut evidence = crate::session::NodeServedEvidence::default();
    #[cfg(test)]
    let work = std::cell::Cell::new(0u64);
    let mut record = |sessions: &FastMap<SessionKey, SyncedSessionEntry>,
                      entry: &SyncedSessionEntry| {
        if entry.tcp_handshake_state != established {
            return false;
        }
        // A pair publishes a distinct session id for its reverse row. Use
        // its canonical forward row as the shared evidence identity so both
        // replica halves compare against the same incarnation baseline.
        let canonical = if entry.metadata.is_reverse {
            #[cfg(test)]
            {
                work.set(work.get() + 1);
            }
            let forward = crate::session::reverse_session_key(&entry.key, entry.decision.nat);
            sessions.get(&forward).unwrap_or(entry)
        } else {
            entry
        };
        evidence.handshake_wire = entry.tcp_handshake_state;
        evidence.shared_established = true;
        evidence.shared_served =
            Some(canonical.fwd_packets.saturating_add(canonical.rev_packets));
        evidence.shared_incarnation = Some((canonical.session_id, canonical.generation));
        evidence.shared_sibling_last_seen_ns = (canonical.sibling_last_seen_ns != 0)
            .then_some(canonical.sibling_last_seen_ns);
        true
    };

    // Keep the primary-map lock for the complete lookup. Publishers and
    // removers update `served_aliases` under this same lock, so a query cannot
    // observe an alias before its primary row, a replacement without its new
    // alias, or a removed primary through a stale alias owner.
    let sessions = lock_shared_recover(shared_sessions);
    #[cfg(test)]
    {
        work.set(work.get() + 1);
    }
    let mut found = false;
    if let Some(entry) = sessions.get(key) {
        // A direct primary hit is authoritative for the probed key and
        // deliberately does not consult alias ambiguity.
        found = record(&sessions, entry);
    }
    if !found {
        let reverse =
            crate::session::reverse_session_key(key, crate::nat::NatDecision::default());
        #[cfg(test)]
        {
            work.set(work.get() + 1);
        }
        if let Some(entry) = sessions.get(&reverse) {
            // A plain-reverse primary hit is still an alias route: its tuple
            // may also be claimed by a translated owner. Require the same
            // unique-owner proof used by the indexed alias path.
            #[cfg(test)]
            {
                work.set(work.get() + 1);
            }
            let owner = lock_shared_recover(&shared_owner_rg_indexes.served_aliases)
                .unique_owner(key)
                .cloned();
            if owner.as_ref() == Some(&entry.key)
                && shared_node_served_entry_claims_alias(entry, key)
            {
                found = record(&sessions, entry);
            }
        }
    }
    if !found {
        #[cfg(test)]
        {
            work.set(work.get() + 1);
        }
        let owner = lock_shared_recover(&shared_owner_rg_indexes.served_aliases)
            .unique_owner(key)
            .cloned();
        if let Some(owner) = owner {
            #[cfg(test)]
            {
                work.set(work.get() + 1);
            }
            if let Some(entry) = sessions.get(&owner)
                && shared_node_served_entry_claims_alias(entry, key)
            {
                let _ = record(&sessions, entry);
            }
        }
    }
    #[cfg(test)]
    NODE_SERVED_WORK_18663.with(|stats| {
        let (calls, total_work) = stats.get();
        stats.set((calls + 1, total_work + work.get()));
    });
    evidence
}

// #18663: the proof counter measures actual keyed lookup work, not table rows.
#[cfg(test)]
thread_local! {
    pub(in crate::afxdp) static NODE_SERVED_WORK_18663: std::cell::Cell<(u64, u64)> =
        const { std::cell::Cell::new((0, 0)) };
}
/// #16223: restamp the shared synced entries for `forward_key` (and
/// its derived reverse companion) to the Established handshake wire
/// once a serving worker completes the pair, so sibling replica
/// tables and the peer-facing expiry probe see node-level proof.
/// Only ever advances Opening/Pending wires to Established; never
/// regresses a close or an already-established row.
/// #16223: advance the shared entries for `key` (any stored
/// orientation, including the SNAT-translated stored key) to
/// Established. Companion to the ct-slice bulk maintenance for
/// callers that already know the completed tuple key.
pub(in crate::afxdp) fn advance_shared_handshake_for_tuple(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) {
    let established = crate::session::TcpHandshakeState::Established.to_wire();
    let reverse_a = crate::session::reverse_session_key(key, crate::nat::NatDecision::default());
    let mut sessions = lock_shared_recover(shared_sessions);
    let targets: Vec<SessionKey> = sessions
        .keys()
        .filter(|stored| {
            let s = *stored;
            (s.src_ip == key.src_ip && s.dst_ip == key.dst_ip && s.src_port == key.src_port && s.dst_port == key.dst_port)
                || (s.src_ip == key.dst_ip && s.dst_ip == key.src_ip && s.src_port == key.dst_port && s.dst_port == key.src_port)
                || (s.src_ip == reverse_a.src_ip && s.dst_ip == reverse_a.dst_ip && s.src_port == reverse_a.src_port && s.dst_port == reverse_a.dst_port)
        })
        .cloned()
        .collect();
    for target in targets {
        if let Some(entry) = sessions.get_mut(&target) {
            if entry.tcp_handshake_state != established {
                entry.tcp_handshake_state = established;
            }
        }
    }
}

pub(in crate::afxdp) fn restamp_shared_handshake_established(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forward_key: &SessionKey,
    nat: crate::nat::NatDecision,
) {
    let established = crate::session::TcpHandshakeState::Established.to_wire();
    let reverse_key = crate::session::reverse_session_key(forward_key, nat);
    let mut sessions = lock_shared_recover(shared_sessions);
    for candidate in [forward_key, &reverse_key] {
        if let Some(entry) = sessions.get_mut(candidate) {
            if entry.tcp_handshake_state != established {
                entry.tcp_handshake_state = established;
            }
        }
    }
}

/// #16217: snapshot a serving pair's ACTUAL reverse packet count
/// onto its shared rows (canonical forward + derived reverse in
/// `shared_sessions`). This is the write side of the fail-closed
/// evidence: only admitted reverse traffic (the forward entry's
/// `counters.rev_packets`, folded by the serving worker) ever raises
/// a row's `rev_packets`; synthesized companions publish 0 and this
/// restamp only ever takes the max, so existence alone never
/// becomes evidence. `shared_sessions` only — no second map, so no
/// lock-order question.
pub(in crate::afxdp) fn restamp_shared_rev_packets(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forward_key: &SessionKey,
    nat: crate::nat::NatDecision,
    rev_packets: u64,
) {
    if rev_packets == 0 {
        return;
    }
    let reverse_key = crate::session::reverse_session_key(forward_key, nat);
    let mut sessions = lock_shared_recover(shared_sessions);
    for candidate in [forward_key, &reverse_key] {
        if let Some(entry) = sessions.get_mut(candidate) {
            entry.rev_packets = entry.rev_packets.max(rev_packets);
        }
    }
}
/// #19063: the restore fence's node-level serving evidence, bound to the
/// incarnation. A restamp raises `last_served_ns` only on a row that carries
/// the SOURCE copy's session id: the forward row, or its reverse companion,
/// which adopts the forward's id (#18718). Without that fence, a delayed
/// restamp of an old incarnation A (another worker's copy, still in its
/// table) would stamp A's service onto its replacement B under the same key
/// and keep idle B copies alive. Counters and `sibling_last_seen_ns` keep
/// their #18742 semantics, untouched here.
#[inline]
fn stamp_last_served(entry: &mut SyncedSessionEntry, source_session_id: u64, packet_seen_ns: u64) {
    if source_session_id != 0 && entry.session_id == source_session_id {
        entry.last_served_ns = entry.last_served_ns.max(packet_seen_ns);
    }
}

/// #19063: the restore fence's shared-row read: the primary row under
/// exactly `key` (one keyed lookup, any protocol), as its session id,
/// max-merged `fwd+rev` counters and `last_served_ns`. Called only for an
/// expiring forward `SharedPromote` copy (GC pass, cold).
pub(in crate::afxdp) fn shared_row_identity(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) -> Option<crate::session::SharedRowIdentity> {
    lock_shared_recover(shared_sessions)
        .get(key)
        .map(|entry| crate::session::SharedRowIdentity {
            session_id: entry.session_id,
            packets: entry.fwd_packets.saturating_add(entry.rev_packets),
            last_served_ns: entry.last_served_ns,
        })
}

/// #16217 (scoped arm): snapshot a serving pair's ACTUAL forward +
/// reverse packet counts onto its shared rows (canonical forward +
/// derived reverse in `shared_sessions`, plus the forward-wire
/// alias slot when the wire map holds one for this tuple). This is
/// the write side of the adoption gate's completed-handshake
/// evidence: only admitted traffic (the forward entry's counters,
/// folded by the serving worker) ever raises a row's counts;
/// synthesized companions publish 0 and this restamp only ever
/// takes the max. Called on the cache-hit packet path ONLY on a
/// handshake stage transition (GLM B1: gate cache-hit restamps
/// behind the transition, never per-packet), so the shared-map lock
/// cost is bounded to one acquisition per completed handshake.
/// Lock order when both maps are taken: `shared_sessions` THEN
/// `shared_forward_wire_sessions` (taken sequentially here, never
/// nested in reverse).
pub(in crate::afxdp) fn restamp_shared_packet_counts(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forward_key: &SessionKey,
    nat: crate::nat::NatDecision,
    source_namespace: u16,
    source_session_id: u64,
    source_packet_seen_ns: u64,
    fwd_packets: u64,
    rev_packets: u64,
) {
    if fwd_packets == 0 && rev_packets == 0 {
        return;
    }
    let reverse_key = crate::session::reverse_session_key(forward_key, nat);
    {
        let mut sessions = lock_shared_recover(shared_sessions);
        for candidate in [forward_key, &reverse_key] {
            if let Some(entry) = sessions.get_mut(candidate) {
                entry.fwd_packets = entry.fwd_packets.max(fwd_packets);
                entry.rev_packets = entry.rev_packets.max(rev_packets);
                stamp_last_served(entry, source_session_id, source_packet_seen_ns);
                if entry.session_id != 0
                    && source_namespace != (entry.session_id >> 48) as u16
                {
                    entry.sibling_last_seen_ns =
                        entry.sibling_last_seen_ns.max(source_packet_seen_ns);
                }
            }
        }
    }
    let wire_key = crate::session::forward_wire_key(forward_key, nat);
    if wire_key != *forward_key {
        let mut wires = lock_shared_recover(shared_forward_wire_sessions);
        if let Some(entry) = wires.get_mut(&wire_key) {
            entry.fwd_packets = entry.fwd_packets.max(fwd_packets);
            entry.rev_packets = entry.rev_packets.max(rev_packets);
        }
    }
}
/// #18655: one ct-slice batch of [`restamp_shared_packet_counts`]. It takes
/// each map's mutex ONCE for the whole batch instead of once per pair, and
/// keeps the same canonical order (`shared_sessions` first, then
/// `shared_forward_wire_sessions`, taken one after the other and never
/// nested). Every row is updated max-only, including its latest sibling
/// packet timestamp; the final state matches calling the single-pair helper
/// for each `(key, nat, fwd, rev, packet_seen_ns, session_id)` in turn.
/// Pairs with zero counts are skipped, as before.
pub(in crate::afxdp) fn restamp_shared_packet_counts_batch(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    source_namespace: u16,
    pairs: &[(SessionKey, crate::nat::NatDecision, u64, u64, u64, u64)],
) {
    if pairs.iter().all(|(_, _, fwd, rev, _, _)| *fwd == 0 && *rev == 0) {
        return;
    }
    {
        let mut sessions = lock_shared_recover(shared_sessions);
        for (forward_key, nat, fwd_packets, rev_packets, source_packet_seen_ns, source_session_id) in
            pairs
        {
            if *fwd_packets == 0 && *rev_packets == 0 {
                continue;
            }
            let reverse_key = crate::session::reverse_session_key(forward_key, *nat);
            for candidate in [forward_key, &reverse_key] {
                if let Some(entry) = sessions.get_mut(candidate) {
                    entry.fwd_packets = entry.fwd_packets.max(*fwd_packets);
                    entry.rev_packets = entry.rev_packets.max(*rev_packets);
                    stamp_last_served(entry, *source_session_id, *source_packet_seen_ns);
                    if entry.session_id != 0
                        && source_namespace != (entry.session_id >> 48) as u16
                    {
                        entry.sibling_last_seen_ns =
                            entry.sibling_last_seen_ns.max(*source_packet_seen_ns);
                    }
                }
            }
        }
    }
    let mut wires = lock_shared_recover(shared_forward_wire_sessions);
    for (forward_key, nat, fwd_packets, rev_packets, _, _) in pairs {
        if *fwd_packets == 0 && *rev_packets == 0 {
            continue;
        }
        let wire_key = crate::session::forward_wire_key(forward_key, *nat);
        if wire_key != *forward_key
            && let Some(entry) = wires.get_mut(&wire_key)
        {
            entry.fwd_packets = entry.fwd_packets.max(*fwd_packets);
            entry.rev_packets = entry.rev_packets.max(*rev_packets);
        }
    }
}

/// #18655: which output slot(s) a shared row with a given `entry.key`
/// contributes to. The bool is `wire_only`: a reverse or forward match
/// (`F`, `R`) vouches in BOTH maps, while a wire-key match (`W`) vouches
/// only in the forward-wire map. These are the #16217 vouching rules,
/// keyed by the row's own `entry.key` and NOT by its map key.
pub(super) type StageCountsWanted = FastMap<SessionKey, Vec<(usize, bool)>>;

/// #18662: at most this many shared rows are fetched during any one
/// stage/count mutex hold, independent of table size.
pub(in crate::afxdp) const STAGE_COUNTS_LOCK_CHUNK_18662: usize = 128;

/// A captured matching row. Its session ID fences retained aliases to the
/// requested output's incarnation while the fold resumes after map unlocks.
struct StageCountsEvidence {
    key: SessionKey,
    session_id: u64,
    is_wire: bool,
    is_reverse: bool,
    stage: u8,
    fwd_packets: u64,
    rev_packets: u64,
}

struct PendingStageCountsFold {
    row: StageCountsEvidence,
    next_slot: usize,
}

/// One incremental traversal for an emit set. The cursor, alias position,
/// pending row folds, output identities, and accumulated results survive each
/// worker-loop return.
pub(in crate::afxdp) struct StageCountsTraversal {
    output_keys: Vec<(SessionKey, crate::nat::NatDecision)>,
    output_identities: Vec<Option<(u64, crate::nat::NatDecision)>>,
    filter_forward_alias_identity: bool,
    wanted: StageCountsWanted,
    requested: Vec<SessionKey>,
    out: Vec<(u8, u64, u64)>,
    key_cursor: usize,
    alias_cursor: usize,
    folds: [Option<PendingStageCountsFold>; STAGE_COUNTS_LOCK_CHUNK_18662],
    folds_len: usize,
    folds_cursor: usize,
}

/// The whole stage/count leg gets a fixed allowance per run_ct_slice call.
/// Each individual map-lock hold remains capped by `STAGE_COUNTS_LOCK_CHUNK_18662`.
pub(in crate::afxdp) const STAGE_COUNTS_INVOCATION_BUDGET_18662: usize = 16_384;

fn stage_counts_evidence(
    entry: &SyncedSessionEntry,
    is_wire: bool,
    wanted: &StageCountsWanted,
) -> Option<PendingStageCountsFold> {
    wanted.get(&entry.key)?;
    Some(PendingStageCountsFold {
        row: StageCountsEvidence {
            key: entry.key.clone(),
            session_id: entry.session_id,
            is_wire,
            is_reverse: entry.metadata.is_reverse,
            stage: entry.tcp_handshake_state,
            fwd_packets: entry.fwd_packets,
            rev_packets: entry.rev_packets,
        },
        next_slot: 0,
    })
}

/// Fold output slots outside locks, charging every slot check to the same
/// invocation budget used for lookup candidates.
fn fold_stage_count_row(
    pending: &mut PendingStageCountsFold,
    wanted: &StageCountsWanted,
    out: &mut [(u8, u64, u64)],
    work: &mut usize,
    work_budget: usize,
    output_identities: &[Option<(u64, crate::nat::NatDecision)>],
    filter_forward_alias_identity: bool,
) {
    let slots = wanted
        .get(&pending.row.key)
        .expect("captured stage-count key remains requested");
    while pending.next_slot < slots.len() && *work < work_budget {
        let (index, wire_only) = slots[pending.next_slot];
        pending.next_slot += 1;
        *work += 1;
        if wire_only && !pending.row.is_wire {
            continue;
        }
        let is_forward_wire_alias = pending.row.is_wire && !pending.row.is_reverse;
        // Reverse companions have independent IDs and remain eligible.
        // Forward rows in the wire map must belong to this output incarnation;
        // this covers the translated wire key and any reverse-key collision.
        if filter_forward_alias_identity
            && is_forward_wire_alias
            && output_identities
                .get(index)
                .and_then(|identity| *identity)
                .map(|(session_id, _)| session_id)
                != Some(pending.row.session_id)
        {
            continue;
        }
        let slot = &mut out[index];
        if !pending.row.is_reverse {
            slot.0 = slot.0.max(pending.row.stage);
        }
        slot.1 = slot.1.max(pending.row.fwd_packets);
        slot.2 = slot.2.max(pending.row.rev_packets);
    }
}

impl StageCountsTraversal {
    fn from_output_keys(
        output_keys: Vec<(SessionKey, crate::nat::NatDecision)>,
        output_identities: Vec<Option<(u64, crate::nat::NatDecision)>>,
        filter_forward_alias_identity: bool,
    ) -> Self {
        debug_assert_eq!(output_keys.len(), output_identities.len());
        let mut wanted: StageCountsWanted = FastMap::default();
        for (index, (forward_key, nat)) in output_keys.iter().enumerate() {
            let reverse_key = crate::session::reverse_session_key(forward_key, *nat);
            let wire_key = crate::session::forward_wire_key(forward_key, *nat);
            wanted.entry(forward_key.clone()).or_default().push((index, false));
            wanted.entry(reverse_key).or_default().push((index, false));
            wanted.entry(wire_key).or_default().push((index, true));
        }
        let requested = wanted.keys().cloned().collect();
        let out = vec![(0u8, 0u64, 0u64); output_keys.len()];
        Self {
            output_keys,
            output_identities,
            filter_forward_alias_identity,
            wanted,
            requested,
            out,
            key_cursor: 0,
            alias_cursor: 0,
            folds: std::array::from_fn(|_| None),
            folds_len: 0,
            folds_cursor: 0,
        }
    }

    /// Fence forward-wire aliases to the output's owner session ID; reverse
    /// companions retain their independently assigned session IDs.
    pub(in crate::afxdp) fn new_with_identities(
        output_keys: Vec<(SessionKey, crate::nat::NatDecision)>,
        output_identities: Vec<Option<(u64, crate::nat::NatDecision)>>,
    ) -> Self {
        Self::from_output_keys(output_keys, output_identities, true)
    }

    #[cfg(test)]
    pub(in crate::afxdp) fn new(
        output_keys: Vec<(SessionKey, crate::nat::NatDecision)>,
    ) -> Self {
        let output_identities = vec![None; output_keys.len()];
        Self::from_output_keys(output_keys, output_identities, false)
    }

    #[cfg(test)]
    fn from_parts(
        wanted: &StageCountsWanted,
        requested: &[SessionKey],
        out: &[(u8, u64, u64)],
    ) -> Self {
        Self {
            output_keys: Vec::new(),
            output_identities: vec![None; out.len()],
            filter_forward_alias_identity: false,
            wanted: wanted.clone(),
            requested: requested.to_vec(),
            out: out.to_vec(),
            key_cursor: 0,
            alias_cursor: 0,
            folds: std::array::from_fn(|_| None),
            folds_len: 0,
            folds_cursor: 0,
        }
    }

    pub(in crate::afxdp) fn output_count(&self) -> usize {
        self.output_keys.len()
    }

    /// Advance by at most `work_budget` total lookup-plus-fold operations.
    /// Returns completion, rows visited, maximum rows in a map-lock hold,
    /// and work charged in this invocation.
    pub(in crate::afxdp) fn advance(
        &mut self,
        shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        wire_index: &Arc<Mutex<SharedEntryKeyIndex>>,
        work_budget: usize,
    ) -> (bool, usize, usize, usize) {
        let budget = work_budget.min(STAGE_COUNTS_INVOCATION_BUDGET_18662);
        let mut work = 0usize;
        let mut total_visited = 0usize;
        let mut max_hold = 0usize;
        while work < budget {
            if self.folds_cursor < self.folds_len {
                let pending = self.folds[self.folds_cursor]
                    .as_mut()
                    .expect("pending stage-count fold slot populated");
                fold_stage_count_row(
                    pending,
                    &self.wanted,
                    &mut self.out,
                    &mut work,
                    budget,
                    &self.output_identities,
                    self.filter_forward_alias_identity,
                );
                let slots_len = self
                    .wanted
                    .get(&pending.row.key)
                    .expect("captured stage-count key remains requested")
                    .len();
                if pending.next_slot == slots_len {
                    self.folds[self.folds_cursor] = None;
                    self.folds_cursor += 1;
                }
                continue;
            }
            if self.key_cursor >= self.requested.len() {
                break;
            }
            self.folds_cursor = 0;
            self.folds_len = 0;
            let hold_start_work = work;
            let mut hold_visited = 0usize;
            {
                let holders = lock_shared_recover(shared_sessions);
                let wires = lock_shared_recover(shared_forward_wire_sessions);
                let wire_index = lock_shared_recover(wire_index);
                while self.key_cursor < self.requested.len() && work < budget {
                    let key = &self.requested[self.key_cursor];
                    if self.alias_cursor == 0 {
                        if work + 2 > budget
                            || work - hold_start_work + 2 > STAGE_COUNTS_LOCK_CHUNK_18662
                        {
                            break;
                        }
                        if let Some(entry) = holders.get(key) {
                            hold_visited += 1;
                            if entry.key == *key
                                && let Some(row) =
                                    stage_counts_evidence(entry, false, &self.wanted)
                            {
                                debug_assert!(self.folds_len < STAGE_COUNTS_LOCK_CHUNK_18662);
                                self.folds[self.folds_len] = Some(row);
                                self.folds_len += 1;
                            }
                        }
                        if let Some(entry) = wires.get(key) {
                            hold_visited += 1;
                            if let Some(row) = stage_counts_evidence(entry, true, &self.wanted) {
                                debug_assert!(self.folds_len < STAGE_COUNTS_LOCK_CHUNK_18662);
                                self.folds[self.folds_len] = Some(row);
                                self.folds_len += 1;
                            }
                        }
                        work += 2;
                    }
                    let Some(map_keys) = wire_index.get(key) else {
                        self.key_cursor += 1;
                        self.alias_cursor = 0;
                        continue;
                    };
                    // The index can shrink between lock chunks; do not leave
                    // the cursor past the new bucket end and spin forever.
                    self.alias_cursor = self.alias_cursor.min(map_keys.len());
                    while self.alias_cursor < map_keys.len()
                        && work < budget
                        && work - hold_start_work < STAGE_COUNTS_LOCK_CHUNK_18662
                    {
                        let slot = self.alias_cursor;
                        self.alias_cursor += 1;
                        work += 1;
                        let alias = &map_keys[slot];
                        if !alias.live || self.wanted.contains_key(&alias.map_key) {
                            continue;
                        }
                        if let Some(entry) = wires.get(&alias.map_key) {
                            hold_visited += 1;
                            if entry.key == *key
                                && let Some(row) =
                                    stage_counts_evidence(entry, true, &self.wanted)
                            {
                                debug_assert!(self.folds_len < STAGE_COUNTS_LOCK_CHUNK_18662);
                                self.folds[self.folds_len] = Some(row);
                                self.folds_len += 1;
                            }
                        }
                    }
                    if self.alias_cursor == map_keys.len() {
                        self.key_cursor += 1;
                        self.alias_cursor = 0;
                    } else {
                        break;
                    }
                }
                drop(wire_index);
                drop(wires);
                drop(holders);
            }
            total_visited += hold_visited;
            max_hold = max_hold.max(hold_visited);
            self.folds_cursor = 0;
            if work == hold_start_work && self.folds_len == 0 {
                // A new key needs two lookup units; if only one remains in
                // this invocation, return the partial traversal unchanged.
                break;
            }
        }
        let complete =
            self.key_cursor >= self.requested.len() && self.folds_cursor >= self.folds_len;
        (complete, total_visited, max_hold, work)
    }

    pub(in crate::afxdp) fn finish(
        self,
    ) -> (
        Vec<(SessionKey, crate::nat::NatDecision)>,
        Vec<Option<(u64, crate::nat::NatDecision)>>,
        Vec<(u8, u64, u64)>,
    ) {
        debug_assert!(self.key_cursor >= self.requested.len());
        debug_assert!(self.folds_cursor >= self.folds_len);
        (self.output_keys, self.output_identities, self.out)
    }
}



pub(in crate::afxdp) fn record_stage_counts_work(
    visited: usize,
    max_hold: usize,
    max_work: usize,
    requested: usize,
) {
    #[cfg(test)]
    STAGE_COUNTS_WORK_18655.with(|work| {
        let (calls, rows, previous_max, previous_work, previous_requested) = work.get();
        work.set((
            calls + 1,
            rows + visited as u64,
            previous_max.max(max_hold as u64),
            previous_work.max(max_work as u64),
            previous_requested + requested as u64,
        ));
    });
    #[cfg(not(test))]
    let _ = (visited, max_hold, max_work, requested);
}

/// Test-only synchronous adapter for direct stage/count checks. The worker
/// loop uses `StageCountsTraversal` directly so bounded work resumes across
/// invocations.
#[cfg(test)]
pub(super) fn stage_and_counts_pass(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    wire_index: &Arc<Mutex<SharedEntryKeyIndex>>,
    wanted: &StageCountsWanted,
    out: &mut [(u8, u64, u64)],
    requested: &[SessionKey],
) -> (usize, usize, usize) {
    stage_and_counts_pass_with_hook(
        shared_sessions,
        shared_forward_wire_sessions,
        wire_index,
        wanted,
        out,
        requested,
        || {},
    )
}

#[cfg(test)]
pub(super) fn stage_and_counts_pass_with_hook<F>(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    wire_index: &Arc<Mutex<SharedEntryKeyIndex>>,
    wanted: &StageCountsWanted,
    out: &mut [(u8, u64, u64)],
    requested: &[SessionKey],
    mut after_chunk: F,
) -> (usize, usize, usize)
where
    F: FnMut(),
{
    let mut traversal = StageCountsTraversal::from_parts(wanted, requested, out);
    let mut total_visited = 0usize;
    let mut max_hold = 0usize;
    let mut max_work = 0usize;
    loop {
        let (complete, visited, hold, work) = traversal.advance(
            shared_sessions,
            shared_forward_wire_sessions,
            wire_index,
            STAGE_COUNTS_LOCK_CHUNK_18662,
        );
        total_visited += visited;
        max_hold = max_hold.max(hold);
        max_work = max_work.max(work);
        after_chunk();
        if complete {
            break;
        }
    }
    out.copy_from_slice(&traversal.out);
    (total_visited, max_hold, max_work)
}



// #18655/#18662: per-thread `(calls, rows fetched, max rows in one mutex
// hold, max lookup-plus-slot-fold work in one invocation, requested worker
// keys)`. The fold contribution makes fan-out work visible in the budget.
#[cfg(test)]
thread_local! {
    pub(in crate::afxdp) static STAGE_COUNTS_WORK_18655: std::cell::Cell<(u64, u64, u64, u64, u64)> =
        const { std::cell::Cell::new((0, 0, 0, 0, 0)) };
}


/// #16217 (ct-slice HA emit), batched by #18655. For each canonical forward
/// key in `keys`, snapshot `(stage_wire, fwd, rev)` from the shared maps
/// (canonical row, derived reverse, forward-wire alias; max counts, max
/// stage over the forward rows). The ct-slice feeds these to
/// `SessionTable::emit_ct_slice_state_update`, so the emitted Update
/// carries the shared row's evidence and not a stale local wire.
///
/// Semantics are those of the pre-#18655 single-key helper, which matched
/// rows by their own `entry.key`:
/// - in `shared_sessions`, rows whose key is the forward key `F` or the
///   reverse key `R`;
/// - in `shared_forward_wire_sessions`, rows whose key is `F`, `R` or the
///   wire key `W`.
///
/// Why not keyed `get()` alone: aliases can remain under a caller-NAT or a
/// displaced key while their row retains a different `entry.key`. The
/// `SharedSessionOwnerRgIndexes` forward-wire directory maps each stable
/// `entry.key` to every live map slot.
/// `StageCountsTraversal` resumes at most `STAGE_COUNTS_INVOCATION_BUDGET_18662`
/// lookup-plus-fold operations per invocation, releasing all map locks before
/// folds and between alias chunks. Each map-lock hold visits at most
/// `STAGE_COUNTS_LOCK_CHUNK_18662` rows or candidates.
///
/// Lock order is `shared_sessions` THEN `shared_forward_wire_sessions`,
/// followed by the wire alias index. This adapter drains bounded chunks
/// synchronously for focused reference tests; production retains its cursor.
#[cfg(test)]
pub(in crate::afxdp) fn shared_rows_stage_and_counts(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    keys: &[(SessionKey, crate::nat::NatDecision)],
) -> Vec<(u8, u64, u64)> {
    let mut out = vec![(0u8, 0u64, 0u64); keys.len()];
    if keys.is_empty() {
        return out;
    }
    let mut wanted: StageCountsWanted = FastMap::default();
    for (index, (forward_key, nat)) in keys.iter().enumerate() {
        let reverse_key = crate::session::reverse_session_key(forward_key, *nat);
        let wire_key = crate::session::forward_wire_key(forward_key, *nat);
        wanted.entry(forward_key.clone()).or_default().push((index, false));
        wanted.entry(reverse_key).or_default().push((index, false));
        wanted.entry(wire_key).or_default().push((index, true));
    }
    let requested: Vec<SessionKey> = wanted.keys().cloned().collect();
    let (visited, max_hold, max_work) = stage_and_counts_pass(
        shared_sessions,
        shared_forward_wire_sessions,
        &shared_owner_rg_indexes.stage_counts_forward_wire_sessions,
        &wanted,
        &mut out,
        &requested,
    );
    record_stage_counts_work(visited, max_hold, max_work, keys.len());
    out
}


/// #16223: periodic maintenance. Advance the shared entries for every
/// ESTABLISHED forward key in `established_keys` to the Established
/// handshake wire. Driven from each worker's conntrack-refresh slice (its
/// own table's completed pairs), so the shared wire that sibling replicas
/// and the expiry probe consult reflects completions that landed on any
/// local hit path (slow-path lookup, update/promotion, cache probe). One
/// lock acquisition per slice; it only ever advances the wire, never
/// regresses it.
pub(in crate::afxdp) fn restamp_shared_handshakes_established(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    established_keys: &[(SessionKey, crate::nat::NatDecision)],
) -> Vec<(SessionKey, crate::nat::NatDecision)> {
    // #16217 (ct-slice HA emit): return the subset whose shared
    // stage TRANSITIONED to Established in this call — the restamp
    // is the transition detector the HA emit keys on. Rows already
    // at wire=4 are not re-reported, so steady-state slices stay
    // silent without any extra bookkeeping here.
    let mut transitioned = Vec::new();
    if established_keys.is_empty() {
        return transitioned;
    }
    let established = crate::session::TcpHandshakeState::Established.to_wire();
    let mut sessions = lock_shared_recover(shared_sessions);
    for (forward_key, nat) in established_keys {
        let reverse_key = crate::session::reverse_session_key(forward_key, *nat);
        let mut advanced = false;
        for candidate in [forward_key, &reverse_key] {
            if let Some(entry) = sessions.get_mut(candidate) {
                if entry.tcp_handshake_state != established {
                    entry.tcp_handshake_state = established;
                    advanced = true;
                }
            }
        }
        if advanced {
            transitioned.push((forward_key.clone(), *nat));
        }
    }
    transitioned
}

/// #16217: advance the forward-wire KEY ALIAS slot
/// (`forward_wire_key(key, decision.nat)`) in
/// `shared_forward_wire_sessions` to Established for a completed
/// forward pair. The canonical restamp lives in
/// `restamp_shared_handshakes_established`; this wrapper owns ONLY
/// the alias slot, which that restamp never writes, so a
/// fabric-ingress adopter looking the NAT'd tuple up directly sees
/// an Established forward entry. Only for wire != key (no-NAT:
/// wire == key: no-op). Never regresses a wire already Established;
/// does not publish deltas. One bounded lock acquisition per call.
/// When the alias slot is absent the canonical row is cloned in
/// WITHOUT rewriting `entry.key` — every legitimate occupant of the
/// wire map retains the canonical key, and
/// `lookup_shared_forward_wire_match` fail-closes unless the
/// ambiguity index records that canonical key as the wire key's
/// owner, so a row keyed by the wire tuple itself could never be
/// adopted.
pub(in crate::afxdp) fn restamp_shared_forward_wire_established(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    established_keys: &[(SessionKey, crate::nat::NatDecision)],
) -> Vec<(SessionKey, crate::nat::NatDecision)> {
    if established_keys.is_empty() {
        return Vec::new();
    }
    let established = crate::session::TcpHandshakeState::Established.to_wire();
    // Lock order: `shared_sessions` THEN `shared_forward_wire_sessions`
    // — the single node-wide order (see `shared_completion_evidence`).
    // Phase 1 (shared_sessions only): snapshot the canonical rows the
    // alias slots may need to clone, then release the guard. Phase 2
    // (forward_wire only): advance or insert. The pre-fix code held
    // the wire guard while locking sessions inside the loop (AB-BA
    // against `shared_completion_evidence`'s sessions-then-wire).
    // #18655: keyed by wire key and first-wins (`or_insert`), the same
    // answer the former `Vec` + `iter().find` gave, but O(1) per key. The
    // linear find ran once per missing alias with the WIRE mutex held,
    // which is O(n^2) under a global lock for a slice of NAT'd keys.
    let mut canonicals: FastMap<SessionKey, SyncedSessionEntry> = FastMap::default();
    {
        let sessions = lock_shared_recover(shared_sessions);
        for (forward_key, nat) in established_keys {
            let wire_key = crate::session::forward_wire_key(forward_key, *nat);
            if wire_key == *forward_key {
                continue;
            }
            if let Some(canonical) = sessions.get(forward_key) {
                canonicals.entry(wire_key).or_insert_with(|| canonical.clone());
            }
        }
    }
    let mut wire_sessions = lock_shared_recover(shared_forward_wire_sessions);
    let mut transitioned = Vec::new();
    for (forward_key, nat) in established_keys {
        let wire_key = crate::session::forward_wire_key(forward_key, *nat);
        if wire_key == *forward_key {
            continue;
        }
        if let Some(entry) = wire_sessions.get_mut(&wire_key) {
            if entry.tcp_handshake_state != established {
                entry.tcp_handshake_state = established;
                transitioned.push((forward_key.clone(), *nat));
            }
        } else if let Some(canonical) = canonicals.get(&wire_key) {
            let mut aliased = canonical.clone();
            aliased.tcp_handshake_state = established;
            let map_key = wire_key.clone();
            wire_sessions.insert(wire_key, aliased);
            // `nat` is captured from this session's installed decision;
            // publish indexed that same wire key. If displaced, its stable
            // tombstone remains, so a completing packet revives the old slot
            // instead of growing the side index on the hot path.
            update_stage_counts_entry_key_index(
                &shared_owner_rg_indexes.stage_counts_forward_wire_sessions,
                &map_key,
                None,
                wire_sessions.get(&map_key),
            );
            transitioned.push((forward_key.clone(), *nat));
        }
    }
    transitioned
}
