//! #9752: flag-driven paced purge of sessions whose installing table is
//! unresolvable — mirrors `delete_drop_sweep.rs` (own file, same shape:
//! budget, cursor, generation-revisit, collect-then-act).
//!
//! Trigger: per-worker `INSTALL_TABLE_PURGE_NEEDED`, set when any re-resolve
//! observes a terminal installing-table outcome. The walk predicate is the D4
//! classifier evaluated against the loop-current registry, so stale flags
//! no-op; a lagging worker whose table was re-added declines everything and
//! converges without deleting.

use super::super::shared_ops::{SharedRemoval, remove_shared_session_if};
use super::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// The most table entries one purge pass may examine. SAME UNIT AND SAME
/// JUSTIFICATION as `DELETE_DROP_SWEEP_BUDGET` (see its comment): the worker
/// does not service its rings while it walks.
pub(in crate::afxdp) const INSTALL_TABLE_PURGE_BUDGET: usize = 256;

/// Resumable purge-walk state, carried across worker-loop passes.
#[derive(Default)]
pub(in crate::afxdp) struct InstallTablePurge {
    cursor: usize,
    running: bool,
    start_fib_generation: u32,
    stale: Vec<SessionKey>,
}

impl InstallTablePurge {
    /// Arm the walk, recording the registry generation it must be revisited
    /// against: a rotation mid-walk restarts rather than completing dirty
    /// (Codex-r4 — consume-at-start, retain-during, revisit-before-clean).
    ///
    /// A request arriving DURING an active walk is retained, not re-armed:
    /// resetting the cursor on every terminal observation would starve all
    /// entries beyond the first budget while observations keep arriving.
    /// The in-flight walk already covers the request (same predicate, same
    /// table set), and its `step` restarts itself on generation change —
    /// overwriting `start_fib_generation` here would defeat that revisit.
    pub(in crate::afxdp) fn arm(&mut self, fib_generation: u32) {
        if self.running {
            return;
        }
        self.cursor = 0;
        self.running = true;
        self.start_fib_generation = fib_generation;
    }

    pub(in crate::afxdp) fn is_running(&self) -> bool {
        self.running
    }

    /// One bounded pass: collect purge-worthy forward keys, tear each down
    /// with its validated companion, replicate conditionally. Returns the
    /// forward count purged this pass; `evicted_keys` feeds flow-cache
    /// invalidation exactly like the delete-drop sweep's.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::afxdp) fn step(
        &mut self,
        sessions: &mut SessionTable,
        session_map: SteeringMap<'_>,
        conntrack_v4_fd: c_int,
        conntrack_v6_fd: c_int,
        shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
        shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
        peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
        forwarding: &ForwardingState,
        shared_runtime: &RuntimeViewReader,
        fib_generation: u32,
        now_ns: u64,
        worker_id: u32,
        evicted_keys: &mut Vec<SessionKey>,
    ) -> usize {
        if !self.running {
            return 0;
        }
        if self.start_fib_generation != fib_generation {
            self.cursor = 0;
            self.start_fib_generation = fib_generation;
        }
        self.stale.clear();
        let next = sessions.iter_with_origin_budgeted(
            self.cursor,
            INSTALL_TABLE_PURGE_BUDGET,
            |key, _origin| {
                // Fresh lookup per key: the budgeted iterator yields key and
                // origin only, and the predicate needs the decision. The walk
                // is single-threaded against its own table, so no mutation
                // can interleave between this check and the teardown below.
                if let Some((decision, metadata, _)) = sessions.entry_with_origin(key) {
                    if !metadata.is_reverse
                        && install_table_purge_predicate(forwarding, key, &decision)
                    {
                        self.stale.push(key.clone());
                    }
                }
            },
        );
        let mut purged = 0usize;
        for key in self.stale.clone() {
            if purge_one_install_table_key(
                sessions,
                session_map,
                conntrack_v4_fd,
                conntrack_v6_fd,
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                shared_owner_rg_indexes,
                peer_worker_commands,
                forwarding,
                shared_runtime,
                &key,
                now_ns,
                worker_id,
                evicted_keys,
            ) {
                purged += 1;
            }
        }
        self.cursor = next;
        if next == 0 {
            self.running = false;
        }
        purged
    }
}

/// #9752: the purge predicate — EXACTLY the sessions D4 would terminalize:
/// nonzero stamp, unresolvable under `forwarding` (unknown domain, owner
/// mismatch, or absent family), with no table-independent local outcome.
/// Shared by the walk, the fenced shared removal, the recipient arm, and the
/// drain's stale-close guard — one classifier (Codex-r4-F4), four call sites.
pub(in crate::afxdp) fn install_table_purge_predicate(
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: &SessionDecision,
) -> bool {
    if decision.install_table_domain == 0 {
        return false;
    }
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };
    let target = resolution_target_for_session(&flow, *decision);
    if !matches!(
        resolve_install_table_for_session(forwarding, *decision, target),
        InstallTable::Unresolvable
    ) {
        return false;
    }
    local_resolution_without_install_table(forwarding, target).is_none()
}

/// #9752: validate a purge companion candidate against its accepted parent
/// (Codex-r4-F1). Derivation alone is insufficient: DNAT can map distinct
/// original destinations onto one translated destination, so distinct same-
/// domain forwards can derive the SAME reverse key (`nat/destination.rs`).
/// The candidate must be reverse, sit at the derived key, invert to the
/// parent's exact tuple through its OWN stored NAT, and carry the expected
/// reversed decision. Anything ambiguous is preserved (linger-safe:
/// default-scoped, validation-gated, age/evict convergent).
pub(super) fn purge_companion_is_linked(
    forward_key: &SessionKey,
    forward_decision: &SessionDecision,
    candidate_key: &SessionKey,
    candidate_decision: &SessionDecision,
    candidate_metadata: &SessionMetadata,
) -> bool {
    if !candidate_metadata.is_reverse {
        // Simultaneous-open guard: a swapped-tuple FORWARD occupying the
        // reverse-wire slot is spared, not torn down with the pair.
        return false;
    }
    if *candidate_key != reverse_session_key(forward_key, forward_decision.nat) {
        return false;
    }
    // Backlink: the candidate's own NAT must invert to the parent's tuple.
    if reverse_session_key(candidate_key, candidate_decision.nat) != *forward_key {
        return false;
    }
    // Expected decision: what install would have set for this companion.
    let expected_nat = forward_decision.nat.reverse(
        forward_key.src_ip,
        forward_key.dst_ip,
        forward_key.src_port,
        forward_key.dst_port,
    );
    candidate_decision.nat == expected_nat
}

/// #9752: tear down one purge-accepted forward key plus its validated
/// companion. Returns whether the forward was acted on (local teardown ran).
/// A fenced-decline still returns true: the local entry is gone (it
/// re-misses and heals) and flow-cache eviction must run — but no close is
/// emitted and nothing is replicated, so shared authority and siblings keep
/// exactly what the fence preserved.
#[allow(clippy::too_many_arguments)]
fn purge_one_install_table_key(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    shared_runtime: &RuntimeViewReader,
    key: &SessionKey,
    now_ns: u64,
    worker_id: u32,
    evicted_keys: &mut Vec<SessionKey>,
) -> bool {
    let Some((decision, metadata, origin)) = sessions.entry_with_origin(key) else {
        return false;
    };
    if metadata.is_reverse || !install_table_purge_predicate(forwarding, key, &decision) {
        return false;
    }
    // Re-check against the LATEST registry before touching anything: a table
    // re-added between the scan and now makes this entry valid again, and
    // tearing down (NAT/BPF churn + re-miss, possibly with a fresh SNAT port)
    // for a valid session is pure damage. A flip-flop (re-added then removed
    // again before the next walk) lingers until age-out or the next terminal
    // touch re-arms — D4 gates every serve, so lingering is memory-lifetime,
    // never wrong forwarding. The in-lock fence below stays authoritative for
    // stamp races the pre-check cannot see.
    if !install_table_purge_predicate(shared_runtime.load().forwarding(), key, &decision) {
        return false;
    }
    let forward_removed = teardown_purge_forward(
        sessions,
        session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        forwarding,
        shared_runtime,
        key,
        &decision,
        &metadata,
        origin,
        now_ns,
        worker_id,
    );
    evicted_keys.push(key.clone());
    if !forward_removed {
        // Fence declined (shared entry changed under us): local teardown ran
        // and flow-cache eviction above covers it, but the pair belongs to
        // live shared authority — no replicate, no companion teardown.
        return true;
    }
    replicate_purge_delete(
        peer_worker_commands,
        key,
        decision.install_table_domain,
        decision.install_table_check,
    );
    // Linked companion (derivation + backlink + expected decision, never
    // replicated — companions converge locally via age/evict/self-purge).
    let companion_key = reverse_session_key(key, decision.nat);
    if companion_key != *key {
        if let Some((c_decision, c_metadata, c_origin)) =
            sessions.entry_with_origin(&companion_key)
        {
            if purge_companion_is_linked(
                key,
                &decision,
                &companion_key,
                &c_decision,
                &c_metadata,
            ) {
                teardown_purge_companion(
                    sessions,
                    session_map,
                    conntrack_v4_fd,
                    conntrack_v6_fd,
                    shared_sessions,
                    shared_nat_sessions,
                    shared_forward_wire_sessions,
                    shared_owner_rg_indexes,
                    key,
                    &decision,
                    &companion_key,
                    &c_decision,
                    &c_metadata,
                    c_origin,
                    forwarding,
                    now_ns,
                    worker_id,
                );
                evicted_keys.push(companion_key);
            }
        }
    }
    true
}

/// #9752: forward-half purge teardown. Mirrors `delete_terminal_half` (NAT
/// release, BPF/conntrack aliases, local table, close delta) with fenced
/// conditional shared removal: the predicate re-loads the LATEST view inside
/// the removal lock, so a table re-added between the walk's scan and this
/// removal declines instead of destroying valid state (Codex-r4-F4). The
/// ArcSwap load is lock-free — no lock cycle with the sessions mutex.
///
/// Returns whether shared authority was actually removed. On decline the
/// local entry is still gone (it re-misses and heals) but NO close delta is
/// emitted: an ordinary Close would sail through the drain, which removes
/// forward+reverse unconditionally and replicates repairing deletes —
/// destroying exactly the shared state the fence preserved and telling every
/// sibling to do the same.
#[allow(clippy::too_many_arguments)]
fn teardown_purge_forward(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    forwarding: &ForwardingState,
    shared_runtime: &RuntimeViewReader,
    key: &SessionKey,
    decision: &SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    now_ns: u64,
    worker_id: u32,
) -> bool {
    release_source_nat_allocation_for_worker(
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        key,
        decision.nat,
        metadata.is_reverse,
        now_ns,
        worker_id,
    );
    crate::nat64::release_nat64_allocation_for_worker(
        &forwarding.nat64,
        key,
        decision.nat,
        metadata.is_reverse,
        now_ns,
        worker_id,
    );
    delete_session_map_entry_for_removed_session_with_origin(
        session_map,
        key,
        *decision,
        metadata,
        origin,
        conntrack_v4_fd,
        conntrack_v6_fd,
    );
    sessions.delete(key);
    let removed = remove_shared_session_if(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        key,
        |entry| {
            entry.decision.install_table_domain == decision.install_table_domain
                && entry.decision.install_table_check == decision.install_table_check
                && install_table_purge_predicate(
                    shared_runtime.load().forwarding(),
                    &entry.key,
                    &entry.decision,
                )
        },
    );
    // Coordinator rows release only when shared authority actually went away
    // (a decline keeps the entry live — releasing would strand it). The close
    // delta is gated the same way: on decline there is nothing to announce,
    // and an ordinary Close would destroy the preserved entry downstream.
    if !matches!(removed, SharedRemoval::Declined) {
        release_coordinator_session_rows(session_map, key);
        sessions.emit_close_delta_with_origin(key.clone(), *decision, metadata.clone(), origin, true);
        true
    } else {
        false
    }
}

/// #9752: companion-half purge teardown. The shared entry must backlink to
/// the accepted forward (same linkage proof); resolvability is NOT required
/// (companions stamp (0,0) by rule R1).
#[allow(clippy::too_many_arguments)]
fn teardown_purge_companion(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    forward_key: &SessionKey,
    forward_decision: &SessionDecision,
    companion_key: &SessionKey,
    companion_decision: &SessionDecision,
    companion_metadata: &SessionMetadata,
    companion_origin: SessionOrigin,
    forwarding: &ForwardingState,
    now_ns: u64,
    worker_id: u32,
) {
    release_source_nat_allocation_for_worker(
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        companion_key,
        companion_decision.nat,
        companion_metadata.is_reverse,
        now_ns,
        worker_id,
    );
    crate::nat64::release_nat64_allocation_for_worker(
        &forwarding.nat64,
        companion_key,
        companion_decision.nat,
        companion_metadata.is_reverse,
        now_ns,
        worker_id,
    );
    delete_session_map_entry_for_removed_session_with_origin(
        session_map,
        companion_key,
        *companion_decision,
        companion_metadata,
        companion_origin,
        conntrack_v4_fd,
        conntrack_v6_fd,
    );
    sessions.delete(companion_key);
    let removed = remove_shared_session_if(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        companion_key,
        |entry| {
            purge_companion_is_linked(
                forward_key,
                forward_decision,
                &entry.key,
                &entry.decision,
                &entry.metadata,
            )
        },
    );
    // Same fence gate as the forward half (today vacuous — the emit fn skips
    // reverse halves — but load-bearing if that ever changes: a declined
    // shared companion must never gain an ordinary Close downstream).
    if !matches!(removed, SharedRemoval::Declined) {
        release_coordinator_session_rows(session_map, companion_key);
        sessions.emit_close_delta_with_origin(
            companion_key.clone(),
            *companion_decision,
            companion_metadata.clone(),
            companion_origin,
            true,
        );
    }
}
