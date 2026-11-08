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
pub(in crate::afxdp) fn shared_completion_evidence(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) -> crate::session::NodeServedEvidence {
    // Both maps, canonical order (shared_sessions first), held
    // together so the two halves of the evidence are one snapshot.
    // Companion keys derive from a canonical row's OWN NAT decision;
    // without a canonical row, the no-NAT companions (identity) still
    // find a plain tuple's reverse row.
    let holders = lock_shared_recover(shared_sessions);
    let wires = lock_shared_recover(shared_forward_wire_sessions);
    let mut ev = crate::session::NodeServedEvidence::default();
    let nat = holders
        .get(key)
        .or_else(|| wires.get(key))
        .map(|e| e.decision.nat)
        .unwrap_or_default();
    let reverse_key = crate::session::reverse_session_key(key, nat);
    let wire_key = crate::session::forward_wire_key(key, nat);
    let rev_wire_key = crate::session::forward_wire_key(&reverse_key, nat);
    for map in [&*holders, &*wires] {
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
/// for each `(key, nat, fwd, rev, packet_seen_ns)` in turn.
/// Pairs with zero counts are skipped, as before.
pub(in crate::afxdp) fn restamp_shared_packet_counts_batch(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    source_namespace: u16,
    pairs: &[(SessionKey, crate::nat::NatDecision, u64, u64, u64)],
) {
    if pairs.iter().all(|(_, _, fwd, rev, _)| *fwd == 0 && *rev == 0) {
        return;
    }
    {
        let mut sessions = lock_shared_recover(shared_sessions);
        for (forward_key, nat, fwd_packets, rev_packets, source_packet_seen_ns) in pairs {
            if *fwd_packets == 0 && *rev_packets == 0 {
                continue;
            }
            let reverse_key = crate::session::reverse_session_key(forward_key, *nat);
            for candidate in [forward_key, &reverse_key] {
                if let Some(entry) = sessions.get_mut(candidate) {
                    entry.fwd_packets = entry.fwd_packets.max(*fwd_packets);
                    entry.rev_packets = entry.rev_packets.max(*rev_packets);
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
    for (forward_key, nat, fwd_packets, rev_packets, _) in pairs {
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

/// #18655: the single pass behind [`shared_rows_stage_and_counts`].
///
/// It visits each row of both maps once. For every output slot that a row
/// vouches for, it folds in the row's stage (forward rows only) and its
/// `fwd` / `rev` counts, all max-only. That is exactly the per-key
/// `map.values()` scan this replaces, run once per row instead of once per
/// row per key. Returns the number of rows visited, so a cell can pin the
/// work at one pass per batch.
pub(super) fn stage_and_counts_pass(
    holders: &FastMap<SessionKey, SyncedSessionEntry>,
    wires: &FastMap<SessionKey, SyncedSessionEntry>,
    wanted: &StageCountsWanted,
    out: &mut [(u8, u64, u64)],
) -> usize {
    let mut visited = 0usize;
    for (map, is_wire) in [(holders, false), (wires, true)] {
        for entry in map.values() {
            visited += 1;
            let Some(slots) = wanted.get(&entry.key) else {
                continue;
            };
            for &(index, wire_only) in slots {
                if wire_only && !is_wire {
                    continue;
                }
                let slot = &mut out[index];
                if !entry.metadata.is_reverse {
                    slot.0 = slot.0.max(entry.tcp_handshake_state);
                }
                slot.1 = slot.1.max(entry.fwd_packets);
                slot.2 = slot.2.max(entry.rev_packets);
            }
        }
    }
    visited
}

// #18655: per-thread `(passes, rows visited)` for
// `shared_rows_stage_and_counts`. Lets a ct-slice cell assert ONE pass
// over the shared maps per slice whatever the batch size. The pre-fix
// per-key scan cost `keys × rows` while holding both global mutexes.
#[cfg(test)]
thread_local! {
    pub(in crate::afxdp) static STAGE_COUNTS_WORK_18655: std::cell::Cell<(u64, u64)> =
        const { std::cell::Cell::new((0, 0)) };
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
/// Why one pass and not keyed `get()`: a forward-wire row is stored under
/// its translated tuple, not under its own `entry.key`. A row is also not
/// always at `forward_wire_key(entry.key, entry.nat)`: the ct-slice alias
/// insert keys it by the caller's NAT, a removal's survivor is reinserted
/// under the removed key, and a republish with a changed NAT leaves the old
/// alias in place (census in `docs/log/18655.md`). So `get(F|R|W)` is not
/// exact. The pass is exact by construction, and it costs
/// `rows(shared) + rows(wire)` per BATCH. The old per-key scan cost
/// `keys × rows` while holding both global mutexes. Every worker holds a
/// copy of every session, so that was quadratic in the node's session
/// count; at 4000 sessions it saturated the mutexes and stalled the whole
/// dataplane (#18655).
///
/// Lock order: `shared_sessions` THEN `shared_forward_wire_sessions`, held
/// together for the pass, as the per-key form held them per key. The
/// wanted-key index is built before the locks are taken. Not inlined: it
/// runs once per slice, and keeping it a real symbol lets a uprobe time
/// the lock-held pass on a live node (the #18655 A/B measures it).
#[inline(never)]
pub(in crate::afxdp) fn shared_rows_stage_and_counts(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
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
    let holders = lock_shared_recover(shared_sessions);
    let wires = lock_shared_recover(shared_forward_wire_sessions);
    let visited = stage_and_counts_pass(&holders, &wires, &wanted, &mut out);
    drop(wires);
    drop(holders);
    #[cfg(test)]
    STAGE_COUNTS_WORK_18655.with(|work| {
        let (passes, rows) = work.get();
        work.set((passes + 1, rows + visited as u64));
    });
    #[cfg(not(test))]
    let _ = visited;
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
            wire_sessions.insert(wire_key, aliased);
            transitioned.push((forward_key.clone(), *nat));
        }
    }
    transitioned
}
