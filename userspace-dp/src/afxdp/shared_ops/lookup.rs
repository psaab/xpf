use super::*;

/// #16217 (scoped completion evidence): reverse + forward packet
/// counts observed for ONE full scoped key (`SessionKey` equality:
/// 5-tuple + routing domain + discriminator) in the shared maps.
/// `shared_completion_evidence` uses the same scoped, keyed form
/// (fold B2); both were bare-tuple full-map scans pre-fold, so a
/// same-tuple row in another VRF could qualify a pending row here
/// (Codex cross-VRF finding).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::afxdp) struct SharedCompletionEvidence {
    pub rev_packets: u64,
    pub fwd_packets: u64,
}

pub(in crate::afxdp) fn lookup_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    // #2402: recover poison so a prior worker panic does not turn every
    // shared-session lookup into a spurious miss.
    lock_shared_recover(shared_sessions).get(key).cloned()
}
/// #16019 fold: node-level reply evidence for the pressure-shed
/// victim check. Reverse-row EXISTENCE is not reply proof — both
/// companions are published at install, before any reply packet.
/// Proof is the reverse row's accounted reverse-packet count:
/// `SyncedSessionEntry::rev_packets`, stamped from the live entry at
/// publish/materialize time (`rev_packets_wire_for`) and folded from
/// the forward entry's counters, so whichever worker accounted the
/// reply leaves `rev_packets > 0` on the shared reverse row every
/// worker consults. TCP rows instead fence on handshake state
/// (Established = 4) inside `is_pressure_shed_shared_unreplied`;
/// this helper covers the non-TCP arm keyed on the reverse tuple
/// derived from the victim's own NAT decision.
pub(in crate::afxdp) fn shared_session_replied(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forward_key: &SessionKey,
    nat: crate::nat::NatDecision,
) -> bool {
    if forward_key.protocol == crate::ip_proto::PROTO_TCP {
        return false;
    }
    let reverse_key = crate::session::reverse_session_key(forward_key, nat);
    if reverse_key == *forward_key {
        return false;
    }
    lookup_shared_session(shared_sessions, &reverse_key)
        .is_some_and(|entry| entry.rev_packets > 0)
}

/// Fabric-ingress adoption (#16217, FZDiag12): does the shared synced
/// map hold a session Established-for-adoption for this exact wire
/// tuple? The packet arrived on the fabric link already SNAT'd by
/// the peer, so its key is the NAT'd wire tuple. The entry may sit
/// under the canonical (pre-NAT) key with this tuple as its
/// forward-wire alias, or directly under the wire key. A forward
/// entry qualifies when EITHER:
///
/// (a) its handshake wire is `Established` (the original rule), OR
/// (b) its wire is `HandshakePending` AND the canonical tuple shows
///     completed-handshake evidence in the shared maps: an actual
///     reverse packet count > 0 on any synced row for the tuple
///     (incl. the reverse companion, fail-closed per FZFixWire6 —
///     synthesized companions carry 0 and never count) AND a
///     forward packet count > 0. This is the DECISION shape: on the
///     new owner the canonical rows stay `SyncImport` +
///     `HandshakePending` forever (every wire-advance collector
///     needs an Established local row the split path never
///     produces), while completion evidence exists only as flow
///     activity — the old owner's flow-cache hits and this node's
///     reverse hits after the failover trickle.
///
/// Scope: the evidence scan compares the FULL scoped key
/// (`SessionKey` equality — 5-tuple + routing domain +
/// discriminator), never `bare_tuple()`: a same-tuple row in
/// another VRF must not qualify this row (Codex cross-VRF finding
/// on the earlier bare-tuple evidence scan). Opening /
/// SynAckFirstPending rows never qualify under (b) — only
/// `HandshakePending`, the state a peer-synced row reaches once
/// the SYN-ACK crossed. Non-TCP entries carry wire 0 and never
/// qualify. Any ambiguity in the wire index fails closed.
pub(in crate::afxdp) fn lookup_shared_established_for_wire(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    wire_key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    let established = crate::session::TcpHandshakeState::Established.to_wire();
    let pending = crate::session::TcpHandshakeState::HandshakePending.to_wire();
    let qualifies = |entry: &SyncedSessionEntry, evidence: SharedCompletionEvidence| -> bool {
        // Callers only reach this for HandshakePending candidates.
        !entry.metadata.is_reverse
            && entry.tcp_handshake_state == pending
            && evidence.rev_packets > 0
            && evidence.fwd_packets > 0
    };
    // Resolve the candidate row(s) first (clone out), then take the
    // evidence snapshot once for the canonical key behind the wire
    // tuple. The direct row's canonical key is itself; the alias
    // row already carries the canonical key on `entry.key`.
    let direct = lookup_shared_session(shared_sessions, wire_key);
    if let Some(entry) = &direct {
        if !entry.metadata.is_reverse && entry.tcp_handshake_state == established {
            return Some(entry.clone());
        }
    }
    let alias = lookup_shared_forward_wire_match(
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        wire_key,
    );
    if let Some(entry) = &alias {
        if !entry.metadata.is_reverse && entry.tcp_handshake_state == established {
            return Some(entry.clone());
        }
    }
    for candidate in [direct, alias].into_iter().flatten() {
        if candidate.metadata.is_reverse
            || candidate.tcp_handshake_state != pending
        {
            continue;
        }
        let evidence = shared_scoped_completion_evidence(
            shared_sessions,
            shared_forward_wire_sessions,
            &candidate.key,
            candidate.decision.nat,
        );
        if qualifies(&candidate, evidence) {
            return Some(candidate);
        }
    }
    None
}
/// #16217 (scoped arm): packet-count evidence for ONE canonical key,
/// read off the shared maps under full scoped-key equality. A row
/// vouches for the canonical tuple when its stored key IS the
/// canonical key, its derived reverse companion
/// (`reverse_session_key(canonical, nat)`), or its forward-wire
/// alias (`forward_wire_key(canonical, nat)`) — all computed from
/// the candidate's own NAT decision, so no bare-tuple scan and no
/// cross-VRF borrowing. On every vouching row both counters count:
/// `rev_packets` is snapshotted from the serving forward entry's
/// admitted reverse counters (a reverse companion carries the
/// pair's reverse count by construction), and `fwd_packets` from
/// its admitted forward counters. A shared row's Established WIRE
/// is deliberately NOT read: it is an output, not evidence.
///
/// Lock order: `shared_sessions` THEN `shared_forward_wire_sessions`
/// — the single node-wide order (see `shared_completion_evidence`).
pub(in crate::afxdp) fn shared_scoped_completion_evidence(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    canonical_key: &SessionKey,
    nat: crate::nat::NatDecision,
) -> SharedCompletionEvidence {
    let reverse_key = crate::session::reverse_session_key(canonical_key, nat);
    let wire_key = crate::session::forward_wire_key(canonical_key, nat);
    let holders = lock_shared_recover(shared_sessions);
    let wires = lock_shared_recover(shared_forward_wire_sessions);
    let mut ev = SharedCompletionEvidence::default();
    // #16217 (folds B2+B5): O(1) keyed gets only — canonical,
    // reverse-companion, and forward-wire alias keys. The pre-fold
    // full-map `values()` scans were O(table) per gate call and
    // (B2) scope-tied to `bare_tuple()` in the sibling
    // `shared_completion_evidence`; keyed gets are scope-exact by
    // construction (full `SessionKey` incl. routing domain +
    // discriminator). The alias slot retains the canonical key on
    // `entry.key`, so canonical/reverse gets cover every map; the
    // wire-key get covers a row stored directly under the NAT'd
    // tuple. A reverse-companion row stored under the wire key is
    // found via the NAT'd reverse companion (`forward_wire_key` of
    // the reverse key), so both NAT'd orientations stay covered.
    let rev_wire_key = crate::session::forward_wire_key(&reverse_key, nat);
    for (map, keys) in [
        (&*holders, [canonical_key, &reverse_key, &wire_key, &rev_wire_key]),
        (&*wires, [canonical_key, &reverse_key, &wire_key, &rev_wire_key]),
    ] {
        for k in keys {
            if let Some(entry) = map.get(k) {
                ev.rev_packets = ev.rev_packets.max(entry.rev_packets);
                ev.fwd_packets = ev.fwd_packets.max(entry.fwd_packets);
            }
        }
    }
    ev
}
/// #16217 (FZDiag16 local-evidence arm): fabric-ingress adoption gate
/// with the worker-local serving table as a second evidence source.
/// The shared maps alone miss the heavy split tuples: on the new owner
/// the shared rows are `SyncImport` replicas imported from the old
/// owner, stuck at HandshakePending (w=2) because every evidence
/// collector excludes peer-synced rows — yet THIS node's worker tables
/// hold the completing pair as local serving rows
/// (`WorkerLocalImport`/`SharedPromote`, wire Established) served on
/// the fabric peer. So: shared Established qualifies as before; else a
/// local non-reverse serving row for the canonical key behind
/// `wire_key` that is fully Established (pending/closing/reverse-only
/// never adopt — `SessionTable::local_established_for_wire_at` fails
/// closed, incl. wire-alias ambiguity and idle expiry) also qualifies.
/// The returned entry is only the gate's boolean-with-provenance: the
/// caller re-resolves through the ordinary session-hit path, which
/// materializes/re-resolves the row and must still yield a local
/// `ForwardCandidate`. For the local arm there is no shared entry to
/// return, so the local canonical key is carried on a cloned local-row
/// snapshot is NOT fabricated — instead this returns `None` entry-wise
/// and the caller uses `local_established_for_wire_at` directly. This
/// wrapper exists so the poll gate has ONE fail-closed predicate:
/// `true` iff either evidence source proves Established.
pub(in crate::afxdp) fn fabric_adoption_established_for_wire(
    sessions: &crate::session::SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    wire_key: &SessionKey,
    now_ns: u64,
) -> bool {
    if lookup_shared_established_for_wire(
        shared_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        wire_key,
    )
    .is_some()
    {
        return true;
    }
    sessions.local_established_for_wire_at(wire_key, now_ns).is_some()
}

/// #16217 (GLM N1): the fabric-adoption gate verified against CURRENT
/// RG ownership. `fabric_adoption_established_for_wire` proves only
/// that the session is Established; it does NOT prove this node owns
/// the egress RG -- a non-owner that somehow holds an Established
/// shared/local row would otherwise adopt and blackhole the flow
/// locally. This wrapper adds the missing half: resolve the wire
/// packet's destination through the live FIB and require the
/// resolution's egress RG (`owner_rg_for_resolution`, tunnel-aware)
/// to be forwarding-active on THIS node right now.
/// #16217 (ownership lag): `forwarding_active_rgs` is the AUTHORITATIVE
/// RG forwarding-active set freshly loaded from the coordinator's
/// `rg_runtime` ArcSwap by the worker loop for THIS packet, NOT the
/// worker's cached per-tick `ha_state` snapshot (which lags RG
/// activation by up to a tick -- at the failover instant it still
/// reads the just-activated RG inactive, so the gate declined every
/// adopted tuple and the packet died `ha_inactive`). The egress RG
/// (and tunnel outer RG) must be in that fresh set; `ha_state` is
/// retained only for the standalone (empty-map) fail-closed shape.
/// Every arm fails closed: no Established evidence, no FIB egress,
/// an unknown egress RG (0), a standalone node, or a departed
/// peer-owned egress RG all decline adoption; the packet then takes
/// the ordinary miss path exactly as before.
/// #16217 (Codex N1 final + N1b): ownership on the EXACT post-NAT
/// per-flow installed-table resolution. The pre-fold gate resolved
/// `wire_key.dst_ip` — the PRE-DNAT destination — destination-only
/// in MAIN, so a tenant flow whose MAIN egress RG is peer-owned but
/// whose tenant-table egress RG is locally owned (or vice versa)
/// was judged on the wrong RG, and a DNAT'd flow was judged on the
/// VIP instead of the real server. Now the candidate's OWN stored
/// decision supplies `nat.rewrite_dst` (post-NAT target),
/// `install_table_domain`/`install_table_check` (validated via
/// `resolve_install_table_for_session`; Unresolvable fails closed),
/// and the per-flow ECMP hash (canonical key), resolved through
/// `lookup_forwarding_resolution_for_session` — the same resolver
/// the re-resolve uses, tunnel arms included. The tunnel outer RG
/// mirrors `enforce_ha_resolution` (ha.rs): GRE/ip6gre via
/// `tunnel_outer_egress_rgs`; WireGuard per-peer via
/// `wireguard_peer_outer_egress_rgs[(endpoint, next_hop)]` with the
/// transport-table FIB fallback for runtime-learned peers (the
/// pre-fold gate read only `tunnel_outer_egress_rgs`, which excludes
/// WG endpoints, and treated absent as success). Absent outer RG,
/// unknown egress RG (0), non-owner, standalone, or no Established
/// evidence all fail closed. `forwarding_active_rgs` is the fresh
/// authoritative set (see the lag note above); `ha_state` is kept
/// only for the standalone empty-map shape and the WG outer fallback
/// is resolved statelessly like ha.rs.
pub(in crate::afxdp) fn fabric_adoption_gate_for_wire(
    forwarding: &crate::afxdp::ForwardingState,
    ha_state: &std::collections::BTreeMap<i32, crate::afxdp::HAGroupRuntime>,
    forwarding_active_rgs: &std::collections::BTreeSet<i32>,
    now_secs: u64,
    sessions: &crate::session::SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    wire_key: &SessionKey,
    now_ns: u64,
    dynamic_neighbors: &Arc<crate::afxdp::ShardedNeighborMap>,
) -> bool {
    let Some(candidate) = adoption_candidate_for_wire(
        sessions,
        shared_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        wire_key,
        now_ns,
    ) else {
        return false;
    };
    if ha_state.is_empty() {
        return false;
    }
    let flow = crate::afxdp::SessionFlow {
        src_ip: candidate.key.src_ip,
        dst_ip: candidate.key.dst_ip,
        forward_key: candidate.key.clone(),
    };
    let resolution = crate::afxdp::session_glue::lookup_forwarding_resolution_for_session(
        forwarding,
        dynamic_neighbors,
        &flow,
        candidate.decision,
    )
    .resolution;
    // #16217 (FZDiag33 death point A): on the standby FIB the
    // connected prefix covering the target is HA-suppressed in
    // `connected_v4` (it survives only in `connected_*_by_ifindex`),
    // so the re-resolution above falls to the pref-200 cluster Null0
    // and answers `ClusterTerminalHAInactive` with egress 0 — even
    // though the candidate's OWN stored decision is a
    // `ForwardCandidate` naming the egress. The stored decision is
    // the ownership proof (the Wire27 shape): the candidate only
    // qualifies with Established/scoped completion evidence, so
    // fall back to its stored egress RG exactly when the
    // re-resolution is that cluster terminal with egress 0. Any
    // other re-resolution (a real candidate, a missing neighbor, a
    // named-egress terminal) is judged as before, and a stored
    // decision that names no known egress RG (0) still declines.
    let egress_rg = crate::afxdp::forwarding::owner_rg_for_resolution(forwarding, resolution);
    let egress_rg = if egress_rg <= 0
        && resolution.disposition
            == crate::afxdp::ForwardingDisposition::ClusterTerminalHAInactive
        && resolution.egress_ifindex <= 0
    {
        crate::afxdp::forwarding::owner_rg_for_resolution(
            forwarding,
            candidate.decision.resolution,
        )
    } else {
        egress_rg
    };
    if egress_rg <= 0 || !forwarding_active_rgs.contains(&egress_rg) {
        return false;
    }
    if resolution.tunnel_endpoint_id != 0 {
        let Some(endpoint) = forwarding.tunnel_endpoints.get(&resolution.tunnel_endpoint_id)
        else {
            return false;
        };
        // Mirror ha.rs: WG selects its outer destination per peer.
        let outer_rg = if endpoint.mode == "wireguard" {
            let Some(next_hop) = resolution.next_hop else {
                return false;
            };
            match forwarding
                .wireguard_peer_outer_egress_rgs
                .get(&(resolution.tunnel_endpoint_id, next_hop))
                .copied()
            {
                Some(rg) if rg >= 0 => Some(rg),
                Some(_) => None,
                None => {
                    let outer_egress = crate::afxdp::forwarding::lookup_forwarding_resolution_inner(
                        forwarding,
                        None,
                        next_hop,
                        Some(&endpoint.transport_table),
                    )
                    .resolution
                    .egress_ifindex;
                    forwarding
                        .egress
                        .get(&outer_egress)
                        .map(|e| e.redundancy_group.max(0))
                }
            }
        } else {
            forwarding
                .tunnel_outer_egress_rgs
                .get(&resolution.tunnel_endpoint_id)
                .copied()
        };
        return match outer_rg {
            Some(rg) if rg > 0 => forwarding_active_rgs.contains(&rg),
            Some(_) => true,
            None => false,
        };
    }
    true
}

/// #16217 (Opus final4 fold): the gate-proved recovery context for
/// `wire_key`, or `None` when the gate declines. Built from the SAME
/// candidate + install-table resolution + fresh-set membership test
/// as `fabric_adoption_gate_for_wire` (single source: the gate is
/// this function plus a tunnel-outer-RG arm the recovery does not
/// re-judge — a tunneled candidate's outer RG stays the gate's
/// answer, and the recovery verifies only the inner egress RG).
/// Poll callsites pass the result into the adopted resolve so the
/// recovery re-resolves in the session's validated install table
/// and restores only candidates whose egress RG == the proved RG.
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn fabric_adoption_recovery_for_wire(
    forwarding: &crate::afxdp::ForwardingState,
    ha_state: &std::collections::BTreeMap<i32, crate::afxdp::HAGroupRuntime>,
    forwarding_active_rgs: &std::collections::BTreeSet<i32>,
    now_secs: u64,
    sessions: &crate::session::SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    wire_key: &SessionKey,
    now_ns: u64,
    dynamic_neighbors: &Arc<crate::afxdp::ShardedNeighborMap>,
) -> Option<crate::afxdp::session_glue::AdoptedRecovery> {
    let candidate = adoption_candidate_for_wire(
        sessions,
        shared_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        wire_key,
        now_ns,
    )?;
    if ha_state.is_empty() {
        return None;
    }
    let flow = crate::afxdp::SessionFlow {
        src_ip: candidate.key.src_ip,
        dst_ip: candidate.key.dst_ip,
        forward_key: candidate.key.clone(),
    };
    let resolution = crate::afxdp::session_glue::lookup_forwarding_resolution_for_session(
        forwarding,
        dynamic_neighbors,
        &flow,
        candidate.decision,
    )
    .resolution;
    let egress_rg = crate::afxdp::forwarding::owner_rg_for_resolution(forwarding, resolution);
    let egress_rg = if egress_rg <= 0
        && resolution.disposition
            == crate::afxdp::ForwardingDisposition::ClusterTerminalHAInactive
        && resolution.egress_ifindex <= 0
    {
        crate::afxdp::forwarding::owner_rg_for_resolution(
            forwarding,
            candidate.decision.resolution,
        )
    } else {
        egress_rg
    };
    if egress_rg <= 0 || !forwarding_active_rgs.contains(&egress_rg) {
        return None;
    }
    let _ = now_secs;
    Some(crate::afxdp::session_glue::AdoptedRecovery {
        decision: candidate.decision,
        flow_key: candidate.key.clone(),
        proved_rg: egress_rg,
    })
}

/// The Established candidate behind `wire_key`: shared Established /
/// scoped-evidence row (its stored key IS the canonical key), else a
/// local Established serving row reified from its stored decision.
/// `None` fails closed (no evidence, ambiguity, idle-crossed).
fn adoption_candidate_for_wire(
    sessions: &crate::session::SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    wire_key: &SessionKey,
    now_ns: u64,
) -> Option<SyncedSessionEntry> {
    if let Some(entry) = lookup_shared_established_for_wire(
        shared_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        wire_key,
    ) {
        return Some(entry);
    }
    let canonical = sessions.local_established_for_wire_at(wire_key, now_ns)?;
    let (decision, metadata, origin) = sessions.entry_with_origin(&canonical)?;
    Some(SyncedSessionEntry {
        key: canonical.clone(),
        decision,
        metadata,
        persistent_lease_hold: sessions.persistent_lease_hold_for(&canonical),
        source_nat_static: None,
        leak_incarnation: 0,
        origin,
        protocol: canonical.protocol,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
        tcp_handshake_state: crate::session::TcpHandshakeState::Established.to_wire(),
        rev_packets: 0,
        fwd_packets: 0,
        pptp_call_ids: 0,
    })
}
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
/// #16223: node-level served-handshake evidence for `key` (either
/// half of the pair): the shared synced entry whose handshake wire is
/// Established. The counter half of the evidence is NOT carried on
/// the shared entry; production merges this wire with the serving
/// worker's admitted-counter stamp (`SessionTable` node-served
/// stamps, surfaced through the expiry context). Either half's key
/// may name the entry, and a reverse key also probes its derived
/// forward companion, so a SNAT-translated reverse replica still
/// finds the serving forward row.
pub(in crate::afxdp) fn shared_node_served_evidence(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) -> crate::session::NodeServedEvidence {
    let mut evidence = crate::session::NodeServedEvidence::default();
    let sessions = lock_shared_recover(shared_sessions);
    let mut probe = |candidate: &SessionKey| {
        if let Some(entry) = sessions.get(candidate) {
            if entry.tcp_handshake_state
                == crate::session::TcpHandshakeState::Established.to_wire()
            {
                evidence.handshake_wire = entry.tcp_handshake_state;
                evidence.shared_established = true;
            }
        }
    };
    probe(key);
    if evidence.handshake_wire == 0 {
        for entry in sessions.values() {
            if entry.tcp_handshake_state
                != crate::session::TcpHandshakeState::Established.to_wire()
            {
                continue;
            }
            let ek = &entry.key;
            let same = ek.bare_tuple() == key.bare_tuple();
            let swapped = ek.src_ip == key.dst_ip
                && ek.dst_ip == key.src_ip
                && ek.src_port == key.dst_port
                && ek.dst_port == key.src_port
                && ek.protocol == key.protocol;
            let derived_reverse = crate::session::reverse_session_key(ek, entry.decision.nat);
            let snat_reverse = derived_reverse.src_ip == key.src_ip
                && derived_reverse.src_port == key.src_port
                && ek.dst_port == key.src_port;
            if same || swapped || snat_reverse {
                evidence.handshake_wire = entry.tcp_handshake_state;
                evidence.shared_established = true;
                break;
            }
        }
    }
    evidence
}
// (The scan in `shared_node_served_evidence` matches the serving
// pair under the opposite orientation or a SNAT-translated reverse
// key; it runs only on idle-crossed GC candidates, never per packet.)

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
/// #16223: periodic maintenance — advance the shared entries for
/// every ESTABLISHED forward key in `established_keys` to the
/// Established handshake wire. Driven from each worker's budgeted
/// conntrack-refresh slice (its own table's completed pairs), so the
/// shared wire that sibling replicas and the expiry probe consult
/// reflects completions that landed on any local hit path (slow-path
/// lookup, update/promotion, cache probe). One lock acquisition per
/// slice; only ever advances the wire, never regresses it.
/// #16217 (ct-slice HA emit): snapshot `(stage_wire, fwd, rev)` for
/// ONE canonical forward key from the shared maps (canonical row,
/// derived reverse, forward-wire alias — max counts, first-found
/// stage on the forward rows). The ct-slice feeds this to
/// `SessionTable::emit_ct_slice_state_update` so the emitted Update
/// carries the shared row's evidence, not a stale local wire. Lock
/// order: `shared_sessions` THEN `shared_forward_wire_sessions`.
pub(in crate::afxdp) fn shared_row_stage_and_counts(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forward_key: &SessionKey,
    nat: crate::nat::NatDecision,
) -> (u8, u64, u64) {
    let reverse_key = crate::session::reverse_session_key(forward_key, nat);
    let wire_key = crate::session::forward_wire_key(forward_key, nat);
    let holders = lock_shared_recover(shared_sessions);
    let wires = lock_shared_recover(shared_forward_wire_sessions);
    let mut stage = 0u8;
    let mut fwd = 0u64;
    let mut rev = 0u64;
    for (map, is_wire) in [(&*holders, false), (&*wires, true)] {
        for entry in map.values() {
            let vouches = if is_wire {
                entry.key == *forward_key || entry.key == reverse_key || entry.key == wire_key
            } else {
                entry.key == *forward_key || entry.key == reverse_key
            };
            if !vouches {
                continue;
            }
            if !entry.metadata.is_reverse {
                stage = stage.max(entry.tcp_handshake_state);
            }
            fwd = fwd.max(entry.fwd_packets);
            rev = rev.max(entry.rev_packets);
        }
    }
    (stage, fwd, rev)
}

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
    let mut canonicals: Vec<(SessionKey, SyncedSessionEntry)> = Vec::new();
    {
        let sessions = lock_shared_recover(shared_sessions);
        for (forward_key, nat) in established_keys {
            let wire_key = crate::session::forward_wire_key(forward_key, *nat);
            if wire_key == *forward_key {
                continue;
            }
            if let Some(canonical) = sessions.get(forward_key).cloned() {
                canonicals.push((wire_key, canonical));
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
        } else if let Some((_, canonical)) = canonicals.iter().find(|(wk, _)| *wk == wire_key) {
            let mut aliased = canonical.clone();
            aliased.tcp_handshake_state = established;
            wire_sessions.insert(wire_key, aliased);
            transitioned.push((forward_key.clone(), *nat));
        }
    }
    transitioned
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
    /// #16217 (FZDiag30): true only when this resolve ran under the
    /// poll fabric-adoption gate's proof (Established + this node is
    /// the post-takeover RG owner). The deferred materialization may
    /// then replace a non-peer-synced local incumbent; every other
    /// resolve keeps the #10582 clobber refusal.
    pub(in crate::afxdp) fabric_adopted: bool,
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
    /// #14941: DIRECTION-RELATIVE — this zone names the HIT packet's egress
    /// leg. On a reverse hit that is the forward flow's ingress zone, not
    /// its egress; persist sites map it through
    /// `forward_egress_zone_for_hit` before handing it to the table.
    pub(in crate::afxdp) new_egress_zone: Option<u32>,
}

/// #14941: map a re-resolve's `new_egress_zone` for the hit direction.
///
/// The resolver's fresh lookup is anchored on the packet that hit the
/// session, so the zone it derives names an egress **for that packet's
/// direction**. The session table's
/// `revalidate_forwarding_resolution_with_egress_zone` expects the
/// FORWARD flow's egress zone (it writes forward `egress_zone` and the
/// reverse companion's `ingress_zone`). For a FORWARD hit the two
/// coincide. For a REVERSE hit they do not: a reverse packet's egress
/// (its route back toward the original client) lives in the forward
/// flow's INGRESS zone, so the zone the reverse lookup just resolved is
/// the pair's updated FORWARD INGRESS zone — the reverse companion's
/// own egress zone — while the forward egress zone (the reverse
/// companion's `ingress_zone`, the zone ACKs must arrive from per
/// #9519) is whatever the reverse companion already records.
///
/// Returns `Some(forward_egress_zone)` only when the forward egress leg
/// actually moves; `None` preserves the recorded pair (terminal routes
/// name no zone, and a reverse re-resolve never names the forward
/// egress). The asymmetric sites below (FabricRedirect's recorded zone,
/// the #9604 forward-companion re-derivations) judge a FORWARD route by
/// construction and keep passing their zone unmapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum ForwardEgressZone {
    /// The zone to persist as the pair's forward egress zone.
    Zone(u32),
    /// No forward-egress move is named; preserve the recorded pair.
    Preserve,
}

impl ForwardEgressZone {
    /// The persistable zone, or `None` to preserve the recorded pair.
    pub(in crate::afxdp) fn as_option(self) -> Option<u32> {
        match self {
            Self::Zone(zone) => Some(zone),
            Self::Preserve => None,
        }
    }
}

/// #14941: direction-relative mapping for a hit-triggered re-resolve.
///
/// `hit_is_reverse` is the matched entry's direction; `resolved_zone` is
/// the zone the fresh lookup named for the HIT packet's egress leg
/// (`None` for terminal routes); `reverse_ingress_zone` is the matched
/// reverse entry's recorded `ingress_zone` (the forward flow's egress
/// zone). A forward hit maps straight through. A reverse hit maps to
/// `Preserve`: its resolved zone belongs to the reverse egress leg
/// (forward ingress), never to the forward egress leg — writing it
/// there flipped `reverse.ingress_zone` WAN->LAN on an ordinary
/// WAN->LAN reroute of the reply path, after which
/// `session_hit_authority` judged every later ACK Foreign, skipped its
/// refresh, and left the session to idle out (#14941/#14300).
pub(in crate::afxdp) fn forward_egress_zone_for_hit(
    hit_is_reverse: bool,
    resolved_zone: Option<u32>,
    reverse_ingress_zone: u32,
) -> ForwardEgressZone {
    if !hit_is_reverse {
        return match resolved_zone {
            Some(zone) => ForwardEgressZone::Zone(zone),
            None => ForwardEgressZone::Preserve,
        };
    }
    // Direction-relative invariant: the forward egress zone after a
    // reverse revalidation is the zone the reverse companion already
    // records as its ingress. Anything the reverse lookup resolved is
    // the opposite leg and must not be written here.
    let _ = resolved_zone;
    let _ = reverse_ingress_zone;
    ForwardEgressZone::Preserve
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
    /// #16042: parsed segment ack for the promote gate (`None` = unparsed).
    pub(in crate::afxdp) ack: Option<u32>,
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

/// #16479 (b): strict-syn-check pre-handshake data drop on a session HIT.
///
/// Returns true when a data-bearing TCP segment must be dropped because
/// the session it hits is a SYN-first session whose three-way handshake
/// is not complete. Mirrors `should_drop_tcp_session_hit_for_flags`'s
/// scope split: the local table is consulted first (read-only probe —
/// a dropped segment never refreshes/promotes/completes the entry);
/// when there is no local entry, the shared maps' carried handshake
/// state (`tcp_handshake_state` 1..=3 = not Established, 0 = legacy
/// established-import) decides, so a peer-synced pending session is
/// gated identically. Established (wire 4, legacy 0, or a locally
/// completed pair) and mid-stream pickups are never gated.
///
/// The `payload_len == 0` / closing / SYN arms live in the leaf
/// predicate `strict_syn_check_drops_pre_handshake_data`; this wrapper
/// only resolves WHICH entry the packet hits and reads its state.
/// Callers must apply the leaf predicate to the returned state (the
/// leaf also re-checks the cheap flag/payload arms).
pub(in crate::afxdp) fn strict_pre_handshake_drop_state(
    sessions: &SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    now_ns: u64,
) -> Option<(bool, bool, bool, bool)> {
    if !matches!(key.protocol, PROTO_TCP) {
        return None;
    }
    if let Some(state) = sessions.strict_pre_handshake_state(key, now_ns) {
        return Some(state);
    }
    // No live local entry: a shared row hit means the poll paths would
    // materialize/serve this tuple, so gate it from the wire handshake
    // state. 1=Opening 2=HandshakePending 3=SynAckFirstPending are all
    // incomplete; 4=Established and 0=legacy-established are not.
    let shared_state = |entry: &SyncedSessionEntry| -> (bool, bool, bool, bool) {
        match entry.tcp_handshake_state {
            1 => (false, false, false, false),
            2 => (true, true, false, false),
            3 => (false, true, true, false),
            _ => (true, false, false, false),
        }
    };
    if let Some(entry) = lookup_shared_session(shared_sessions, key) {
        return Some(shared_state(&entry));
    }
    lookup_shared_forward_wire_match(shared_forward_wire_sessions, shared_owner_rg_indexes, key)
        .map(|entry| shared_state(&entry))
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
    // #14937: test-only — no packet frame, so payload is honestly 0.
    lookup_session_across_scopes_with_shared_and_payload(
        sessions,
        shared_sessions,
        &shared_nat_sessions,
        shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        key,
        now_ns,
        tcp_flags,
        0,
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
    // #14937: test-only — no packet frame, so payload is honestly 0.
    lookup_session_across_scopes_with_shared_and_payload(
        sessions,
        shared_sessions,
        &shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        key,
        now_ns,
        tcp_flags,
        0,
    )
}

/// #9990: non-mutating counterpart to [`lookup_session_across_scopes_with_shared_and_payload`].
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
    Zone(u32),
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
        synced_synthesis: false,
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
    // #16014: local AMBIGUOUS is terminal — never fall through to shared.
    let local_match = match now_ns {
        Some(now) => match sessions.find_forward_nat_match_expiry(reply_key, now, &egress_domain) {
            crate::session::ForwardNatExpiryProbe::Live(hit) => Some(hit),
            crate::session::ForwardNatExpiryProbe::IdleCrossed => {
                // Do not resurrect an expired local entry from its shared clone.
                return None;
            }
            crate::session::ForwardNatExpiryProbe::Ambiguous => return None,
            crate::session::ForwardNatExpiryProbe::Absent => None,
        },
        None => match sessions.find_forward_nat_match_lookup(reply_key, &egress_domain) {
            crate::session::ForwardNatMatchLookup::Unique(hit) => Some(hit),
            crate::session::ForwardNatMatchLookup::Ambiguous => return None,
            crate::session::ForwardNatMatchLookup::NoMatch => None,
        },
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
                synced_synthesis: false,
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
        synced_synthesis: false,
    })
}
