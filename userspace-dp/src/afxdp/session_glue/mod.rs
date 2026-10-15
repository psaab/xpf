use super::*;
use crate::session::ForwardingGenerationStamp;
use std::sync::atomic::{AtomicU64, Ordering};

pub(in crate::afxdp) mod commands;
mod delete_drop_sweep;
mod install_table_purge;
mod promote;

pub(in crate::afxdp) use delete_drop_sweep::{DELETE_DROP_SWEEP_BUDGET, DeleteDropSweep};
pub(in crate::afxdp) use install_table_purge::{
    INSTALL_TABLE_PURGE_BUDGET, InstallTablePurge, install_table_purge_predicate,
};
pub(in crate::afxdp) use promote::{
    SharedSessionRefs, maybe_promote_synced_session, maybe_promote_synced_session_with_conntrack,
    SessionHitVerdict,
};
/// #10507 Cell 5a test seam: command-driven Demote/Refresh funnels for
/// cross-module poll tests (unshared map, no BPF). Production `handle_*`
/// stay `pub(in session_glue)`; these `#[cfg(test)]` delegates widen
/// nothing outside tests.
#[cfg(test)]
pub(crate) fn handle_demote_owner_rgs_for_test(
    sessions: &mut crate::session::SessionTable,
    session_map: crate::afxdp::bpf_map::SteeringMap<'_>,
    conntrack_v4_fd: libc::c_int,
    conntrack_v6_fd: libc::c_int,
    forwarding: &crate::afxdp::ForwardingState,
    ha_state: &std::collections::BTreeMap<i32, crate::afxdp::HAGroupRuntime>,
    dynamic_neighbors: &std::sync::Arc<crate::afxdp::sharded_neighbor::ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
    cancelled_keys: &mut Vec<crate::session::SessionKey>,
    cancelled_keys_seen: &mut rustc_hash::FxHashSet<crate::session::SessionKey>,
) -> bool {
    commands::handle_demote_owner_rgs(
        sessions, session_map, conntrack_v4_fd, conntrack_v6_fd, forwarding,
        ha_state, dynamic_neighbors, owner_rgs, now_ns, now_secs,
        cancelled_keys, cancelled_keys_seen,
    )
}
#[cfg(test)]
pub(crate) fn handle_refresh_owner_rgs_for_test(
    sessions: &mut crate::session::SessionTable,
    session_map: crate::afxdp::bpf_map::SteeringMap<'_>,
    forwarding: &crate::afxdp::ForwardingState,
    ha_state: &std::collections::BTreeMap<i32, crate::afxdp::HAGroupRuntime>,
    dynamic_neighbors: &std::sync::Arc<crate::afxdp::sharded_neighbor::ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
) -> bool {
    commands::handle_refresh_owner_rgs(
        sessions, session_map, forwarding, ha_state, dynamic_neighbors,
        owner_rgs, now_ns, now_secs,
    )
}
use promote::{purge_translated_synced_hit, should_keep_synced_hit_transient};

mod resolution;
mod worker_commands;
mod revalidation;
mod tx_cancel;
mod resolve;
#[cfg(test)]
mod modularity_13082_tests;
pub(super) use resolution::*;
pub(super) use worker_commands::*;
pub(super) use revalidation::*;
pub(super) use tx_cancel::*;
pub(super) use resolve::*;
pub(crate) use resolution::{INSTALL_TABLE_PURGE_NEEDED, policy_id_for_list_request};
pub(crate) use revalidation::{
    forward_export_candidates_for_owner_rgs, publish_worker_session_map_entry,
};
#[cfg(test)]
pub(crate) use revalidation::export_forward_sessions_for_owner_rgs;
pub(crate) use worker_commands::{
    PEER_DELETE_REFUSED_LOCAL_OWNED, SESSION_DELETE_DROP_EPOCH,
    SESSION_DELETE_REPLICA_DROPPED, SESSION_DELETE_REPLICA_DROP_REPAIRED,
    SESSION_REPLICATION_ENQUEUED, SESSION_REPLICATION_LOCK_CONTENDED,
    SESSION_REPLICATION_QUEUE_DEPTH_MAX, SESSION_REPLICATION_QUEUE_DEPTH_SUM,
    SESSION_REPLICATION_UPSERTS, session_delete_drop_epoch,
};

pub(crate) fn export_forward_sessions_for_owner_rgs(
    sessions: &mut SessionTable,
    owner_rgs: &[i32],
) {
    for (key, decision, metadata, origin) in
        forward_export_candidates_for_owner_rgs(sessions, owner_rgs, u64::MAX)
    {
        sessions.emit_open_delta_with_origin(key, decision, metadata, origin, true);
    }
}

/// Apply due #11360 repairs from the current shared authority. These must run
/// at their queue boundary and before later queued commands; stale replay
/// filtering and eviction use the same worker-loop path as queued upserts.
/// If a later delete removed the shared row, run the existing worker delete
/// path so an earlier queued upsert cannot leave stale local state behind.
pub(in crate::afxdp) fn apply_session_import_repairs(
    repairs: &[worker_queue::SessionImportRepair],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    stale_replay_dropped_keys: &mut Vec<SessionKey>,
    deleted_synced_keys: &mut Vec<SessionKey>,
    worker_id: u32,
) {
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let entries = {
        let shared = crate::afxdp::shared_ops::lock_shared_recover(shared_sessions);
        repairs
            .iter()
            .map(|repair| (repair.clone(), shared.get(&repair.key).cloned()))
            .collect::<Vec<_>>()
    };
    for (repair, entry) in entries {
        if let Some(entry) = entry {
            if synced_entry_is_stale_replay(entry.origin, &entry.metadata, forwarding) {
                note_stale_replay_fence_drop();
                stale_replay_dropped_keys.push(entry.key.clone());
            } else {
                commands::handle_upsert_synced(
                    sessions,
                    session_map,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    entry,
                    now_ns,
                    now_secs,
                    worker_id,
                );
            }
        } else {
            commands::handle_delete_synced(
                sessions,
                session_map,
                forwarding,
                ha_state,
                repair.key.clone(),
                now_ns,
                now_secs,
                deleted_synced_keys,
                worker_id,
            );
        }
        worker_queue::complete_session_import_repair(worker_id, &repair);
    }
}

pub(super) fn apply_worker_commands(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    // #6211 F2: THIS worker's id, threaded from `WorkerLaunchPlan::worker_id`
    // in the worker loop. A peer-synced reservation is held by every worker, so
    // a release must drop THIS worker's bit rather than free the port outright.
    worker_id: u32,
    // #7201: worker-owned, recycled across calls. The drain moves its bounded
    // slice in here instead of `mem::take`-ing the shared deque, so the shared
    // deque keeps its allocation (the producers hold the lock; they were paying
    // to regrow it from zero capacity on every pass) and this buffer keeps its
    // own. Entered empty and left empty — the dispatch loop below drains it.
    scratch: &mut VecDeque<WorkerCommand>,
) -> WorkerCommandResults {
    // Sample monotonic time ONCE per tick so every handler sees the same
    // `now_ns` / `now_secs` and there is no intra-tick clock skew between
    // session-table side effects (#1346 plan v2 invariant 3).
    // (Sampled above the drain: the #9720 debt handlers below share the tick.)
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let mut cancelled_keys: Vec<SessionKey> = Vec::new();
    // #6457: keys dropped by `DeleteSynced` this tick, drained by the
    // worker loop into per-binding flow-cache invalidations (the struct
    // field comment carries the full rationale). Not pre-sized — delete
    // bursts are control-plane paced and the common no-delete tick pays
    // no allocation (same policy as `cancelled_keys`).
    let mut deleted_synced_keys: Vec<SessionKey> = Vec::new();
    // #10612: keys refused by the stale-replay fence this tick (see the
    // `UpsertSynced` arm); drained by the worker loop into shared-map
    // evictions. Not pre-sized — drops are control-plane paced and the
    // common no-drop tick pays no allocation (same policy as its neighbors).
    let mut stale_replay_dropped_keys: Vec<SessionKey> = Vec::new();
    // #5155: companion dedup set for `handle_demote_owner_rgs`. Kept
    // beside `cancelled_keys` (not pre-sized) so the O(1) membership
    // test persists across the multiple DemoteOwnerRGS arms in one
    // dispatch loop while common (no-demote) ticks pay no allocation.
    let mut cancelled_keys_seen: rustc_hash::FxHashSet<SessionKey> =
        rustc_hash::FxHashSet::default();
    let mut exported_sequences = Vec::new();
    let mut session_counter_answers: Vec<SessionCounterAnswer> = Vec::new();
    let mut export_owner_rgs: Vec<i32> = Vec::new();
    // #9856: first-accept-wins kick epoch for this tick's export (None when
    // no Export command accepted). Kept out of the debt-step/gate regions.
    let mut export_kick_epoch: Option<u64> = None;
    let mut shaped_tx_requests = Vec::new();
    let mut vacate_all_shared_exact_slots = false;
    // Hot path: try_lock avoids blocking on the mutex when another thread
    // holds it (rare) and avoids the cost of lock+unlock on empty queues
    // when there's nothing to do (common case during steady-state forwarding).
    // #1807: a poisoned mutex is recovered (committed-prefix + clear_poison
    // policy, worker_queue.rs) and the recovered deque is processed as
    // normal — treating poison as absence-of-work made the worker
    // permanently deaf to coordinator commands.
    //
    // #7201: this takes a BOUNDED PREFIX, not the whole deque. Every command is
    // a session-table mutation plus a BPF-map publish syscall, and the worker
    // does not touch its AF_XDP rings until the loop below finishes — so an
    // unbounded drain is unserviced ring time. See
    // `worker_queue::WORKER_COMMAND_DRAIN_BUDGET` for the measurement and the
    // ring arithmetic that fix the slice size.
    //
    // #9720: no early returns — the debt step below must run on every path
    // (an empty queue still steps a zero-countdown op ready; a contended one
    // still reports the carry flag), so an empty or contended queue falls
    // through with an empty scratch (a no-op dispatch) instead of returning.
    // `scratch_len_before` deltas the drain: scratch enters empty by
    // invariant, but the delta stays correct even for a test-reused buffer.
    let (mut session_import_repairs, ready_remains_at_start, mut session_import_repair_pending) =
        worker_queue::take_ready_session_import_repairs(
            worker_id,
            worker_queue::SESSION_IMPORT_REPAIR_DRAIN_BUDGET,
        );
    let repair_due_at_start = !session_import_repairs.is_empty() || ready_remains_at_start;
    let scratch_len_before = scratch.len();
    let (commands_backlogged, queue_lock_acquired) = if repair_due_at_start {
        let backlogged = worker_queue::try_lock_recover(commands)
            .map(|pending| !pending.is_empty())
            .unwrap_or(false);
        (backlogged, false)
    } else {
        match worker_queue::try_lock_recover(commands) {
            Some(mut pending) => {
                let backlogged = if pending.is_empty() {
                    false
                } else {
                    // #11718: stop the budgeted slice at the nearest repair
                    // boundary; its later FIFO suffix stays queued for after
                    // the shared-authority repair has been applied.
                    let drain_limit = if session_import_repair_pending {
                        worker_queue::session_import_repair_drain_limit(
                            worker_id,
                            worker_queue::WORKER_COMMAND_DRAIN_BUDGET,
                        )
                    } else {
                        worker_queue::WORKER_COMMAND_DRAIN_BUDGET
                    };
                    worker_queue::drain_bounded_into_with_limit(
                        &mut pending,
                        scratch,
                        drain_limit,
                    )
                };
                let drained = scratch.len() - scratch_len_before;
                // Capture the drain while still holding the same queue lock
                // used by importers to assign repair positions. A refused
                // import records its debt after releasing that lock.
                worker_queue::note_worker_commands_drained(worker_id, drained);
                let (ready, _, pending_repairs) =
                    worker_queue::take_ready_session_import_repairs(
                        worker_id,
                        worker_queue::SESSION_IMPORT_REPAIR_DRAIN_BUDGET,
                    );
                session_import_repairs = ready;
                session_import_repair_pending = pending_repairs;
                (backlogged, true)
            }
            None => {
                session_import_repair_pending =
                    worker_queue::has_session_import_repair_debt(worker_id);
                // The queue is not known to be empty — a producer holds it.
                (false, false)
            }
        }
    };
    let drained = scratch.len() - scratch_len_before;
    for cmd in scratch.drain(..) {
        match cmd {
            WorkerCommand::DemoteOwnerRGS { owner_rgs } => {
                // #9752: a terminal demote arms the purge walk (D8).
                if commands::handle_demote_owner_rgs(
                    sessions,
                    session_map,
                    conntrack_v4_fd,
                    conntrack_v6_fd,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    owner_rgs,
                    now_ns,
                    now_secs,
                    &mut cancelled_keys,
                    &mut cancelled_keys_seen,
                ) {
                    flag_install_table_purge(worker_id);
                }
            }
            WorkerCommand::RefreshOwnerRGS { owner_rgs } => {
                // #9752: a terminal refresh arms the purge walk (D8).
                if commands::handle_refresh_owner_rgs(
                    sessions,
                    session_map,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    owner_rgs,
                    now_ns,
                    now_secs,
                ) {
                    flag_install_table_purge(worker_id);
                }
            }
            WorkerCommand::ExportOwnerRGSessions {
                sequence,
                owner_rgs,
            } => {
                commands::handle_export_owner_rg_sessions(
                    sessions,
                    &mut exported_sequences,
                    &mut export_owner_rgs,
                    &mut export_kick_epoch,
                    sequence,
                    owner_rgs,
                );
            }
            WorkerCommand::QuerySessionCounters { sequence, key } => {
                // READ-ONLY. `counters_with_replica_flag` looks the key up
                // without touching the table; nothing here installs, refreshes
                // or expires anything. A diagnostic that perturbed the state it
                // reports would be worse than no diagnostic.
                let answer = match sessions.counters_with_replica_flag(&key) {
                    Some((counters, replica)) => SessionCounterAnswer {
                        sequence,
                        found: true,
                        replica,
                        fwd_packets: counters.fwd_packets,
                        fwd_bytes: counters.fwd_bytes,
                        rev_packets: counters.rev_packets,
                        rev_bytes: counters.rev_bytes,
                    },
                    None => SessionCounterAnswer {
                        sequence,
                        found: false,
                        replica: false,
                        fwd_packets: 0,
                        fwd_bytes: 0,
                        rev_packets: 0,
                        rev_bytes: 0,
                    },
                };
                session_counter_answers.push(answer);
            }
            WorkerCommand::ListSessionsByPolicy {
                request,
                collected,
                overflow,
                errors,
                pending,
            } => {
                let wanted = |policy_id: u32| {
                    policy_id != 0 && request.policy_ids.iter().any(|candidate| *candidate == policy_id)
                };
                let family_allowed = |family: u8| {
                    request.families.is_empty()
                        || request
                            .families
                            .iter()
                            .any(|candidate| *candidate == family)
                };
                let class_allowed = |is_reverse: bool| {
                    request.classes.is_empty()
                        || request.classes.iter().any(|class| {
                            (is_reverse && class == "reverse")
                                || (!is_reverse && class == "forward")
                        })
                };
                if request.mode == "legacy" && request.before_secs.is_none() {
                    errors
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push("legacy-before-secs-missing".to_string());
                } else {
                    sessions.iter_with_identity(
                        |key, decision, metadata, origin, created_ns, session_id| {
                            let family = crate::afxdp::ha::policy_wire_family(key.addr_family);
                            if !family_allowed(family) || !class_allowed(metadata.is_reverse) {
                                return;
                            }
                            let Some(policy_id) = policy_id_for_list_request(
                                forwarding,
                                metadata,
                                origin,
                                &request.mode,
                            ) else {
                                return;
                            };
                            if !wanted(policy_id) {
                                return;
                            }
                            // Legacy time fence (#6948): keep sessions admitted
                            // at or before the activation stamp (old numbering).
                            // `Some(0)` is explicitly UNBOUNDED — Go sends the
                            // raw activation stamp, and 0 means "boundary
                            // unknown" (clear every matching id), never a real
                            // timestamp. `None` in legacy mode is a caller bug
                            // and is rejected above, not silently unbounded.
                            if request.mode == "legacy"
                                && request
                                    .before_secs
                                    .map(|before| {
                                        before != 0 && created_ns / 1_000_000_000 > before
                                    })
                                    .unwrap_or(true)
                            {
                                return;
                            }
                            if session_id == 0 {
                                errors
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .push(format!(
                                        "identity-missing:{}:{}",
                                        key.src_ip, key.dst_ip
                                    ));
                                return;
                            }
                            // Shared admission: skip fast past the cap (no
                            // lock), else reserve (dedups cross-worker
                            // replicas) BEFORE building the row. The build
                            // below runs unlocked; only reserve and push take
                            // the collector lock.
                            if overflow.load(std::sync::atomic::Ordering::Acquire) {
                                return;
                            }
                            let admitted = collected
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .reserve(overflow.as_ref(), key.clone(), session_id);
                            if !admitted {
                                return;
                            }
                            let Some(mut row) = crate::afxdp::ha::policy_match_from_parts(
                                key,
                                metadata,
                                decision.nat,
                                session_id,
                                created_ns,
                            ) else {
                                errors
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .push("unsupported-address-family".to_string());
                                return;
                            };
                            row.policy_id = policy_id;
                            if let Some((companion_key, _, companion_id)) =
                                sessions.policy_companion(key, decision.nat)
                            {
                                if companion_id == 0 {
                                    errors
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                                        .push(format!(
                                            "companion-identity-missing:{}:{}",
                                            key.src_ip, key.dst_ip
                                        ));
                                    return;
                                }
                                row.reverse_key =
                                    crate::afxdp::ha::policy_tuple_from_key(&companion_key);
                                if row.reverse_key.is_none() {
                                    errors
                                        .lock()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                                        .push("unsupported-companion-family".to_string());
                                    return;
                                }
                                row.expected_companion_rt_flow_session_id = companion_id;
                            }
                            collected
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .push(row);
                        },
                    );
                }
                pending.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
            WorkerCommand::UpsertSynced(entry) => {
                // #10612: fence a stale replay behind the rotation purge. A
                // pre-purge snapshot re-published post-purge (backlog, late
                // fan-out, re-import) must not reinstall the removed-zone row
                // the purge deleted. Dropped here — before re-resolve, install,
                // reserve, publish — and the key recorded so the worker loop
                // evicts the stale row from shared authority (same
                // record-here/evict-where-the-handles-are split as #6457).
                if synced_entry_is_stale_replay(entry.origin, &entry.metadata, forwarding) {
                    note_stale_replay_fence_drop();
                    stale_replay_dropped_keys.push(entry.key);
                } else {
                    commands::handle_upsert_synced(
                        sessions,
                        session_map,
                        forwarding,
                        ha_state,
                        dynamic_neighbors,
                        entry,
                        now_ns,
                        now_secs,
                        worker_id,
                    );
                }
            }
            WorkerCommand::UpsertLocal(entry) => {
                // Kept inline (#1346 plan v2 §4.1): lifting a short
                // delegate to its own sibling file is negative value.
                //
                // #1870: local-tunnel pair entries are coordinator-
                // authoritative replicas of state ALREADY published to
                // the shared maps (the tunnel.rs publish precedes the
                // enqueue). Routing them through the capped
                // install_with_protocol_with_origin let max_sessions
                // refuse the worker-table copy while the reactive
                // shared-hit materialization
                // (materialize_shared_session_hit) reinstalls the
                // reverse entry uncapped on the next reply packet — a
                // futile cap that only polluted create_drops and
                // delayed/voided the prewarm. Use the uncapped
                // sync-family install these SyncImport-origin entries
                // belong to. allow_replace_local=true preserves the
                // pre-#1870 replace semantics (the capped install
                // clobbered any same-key entry below cap); the data is
                // locally generated — the producer only runs when the
                // tunnel resolution is ForwardCandidate
                // (build_local_origin_tunnel_tx_request) — so the
                // "don't let peer data clobber local sessions" guard
                // does not apply.
                debug_assert!(
                    entry.origin.is_peer_synced(),
                    "UpsertLocal entries must carry a sync-family origin; a \
                     local origin would have pushed an HA delta on the old \
                     install path"
                );
                // #5212 / #9412: the shared mapping preserves the entry's id (a
                // local-tunnel replica carries 0 => fresh local alloc) and its
                // close class.
                let installed = sessions.upsert_synced_with_origin(
                    entry.into_session_install(now_ns),
                    /* allow_replace_local = */ true,
                );
                // The only false exit is the local-clobber guard, which
                // allow_replace_local=true bypasses — infallible by
                // construction (#1855 contract: assert in debug, inert
                // in release).
                debug_assert!(
                    installed,
                    "upsert_synced_with_origin(_, true) is infallible"
                );
                let _ = installed;
            }
            WorkerCommand::DeleteSynced(key) => {
                commands::handle_delete_synced(
                    sessions,
                    session_map,
                    forwarding,
                    ha_state,
                    key,
                    now_ns,
                    now_secs,
                    &mut deleted_synced_keys,
                    worker_id,
                );
            }
            WorkerCommand::DeleteSyncedConditional { key, expected_id, companion } => {
                commands::handle_delete_synced_conditional(
                    sessions,
                    session_map,
                    forwarding,
                    ha_state,
                    key,
                    expected_id,
                    now_ns,
                    now_secs,
                    &mut deleted_synced_keys,
                    worker_id,
                    companion,
                );
            }
            WorkerCommand::DeletePolicyBatch {
                items,
                applied,
                pending,
                report,
                intents,
            } => {
                // Abort fence, phase 1 (table work ONLY): hold the report
                // mutex across cancel-check and the per-item teardown loop, so
                // cancel validation is atomic with the table mutations (see
                // PolicyDeleteBatchReport). Microsecond, syscall-free, and
                // tree-standard to hold — BPF redirect deletes are collected
                // as intents and stashed into the shared handoff INSIDE this
                // scope (table-side metadata only): holding syscalls would let
                // a slow worker wedge the coordinator's abort indefinitely,
                // and post-fence worker BPF would break abort-quiescence.
                // The coordinator drains + executes after phase-1 acks, under
                // the batch lease. Lock order fence -> applied slot / intents,
                // never reversed: the coordinator reads slots and drains
                // intents without the fence (after all acks) and takes the
                // fence touching neither (on abort).
                {
                    let mut guard = report
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if !guard.cancelled {
                        let mut applied_slot = applied
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        let mut deferred = Vec::new();
                        for (index, item) in items.iter().enumerate() {
                            if commands::handle_remove_policy_item(
                                sessions,
                                session_map,
                                forwarding,
                                ha_state,
                                item,
                                &mut *guard,
                                index,
                                now_ns,
                                now_secs,
                                &mut deleted_synced_keys,
                                worker_id,
                                &mut deferred,
                            ) {
                                applied_slot[index] = true;
                            }
                        }
                        intents
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .extend(deferred);
                    }
                }
                pending.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
            WorkerCommand::ProbePolicyBatch {
                bares,
                found,
                pending,
            } => {
                commands::handle_probe_policy_tuples(sessions, &bares, found.as_ref());
                pending.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
            }
            WorkerCommand::DeleteSyncedIfTableUnknown { key, domain, check } => {
                // #9752: conditional purge delete — decline (no-op, not even
                // `deleted_keys`: the entry survives so its flow-cache permit
                // stays backed, the #9048 reasoning) unless OUR entry still
                // carries this stamp AND is unresolvable under CURRENT
                // registry. Lagging senders, re-added tables, and
                // Companions are not replicated: they converge locally
                // (age/evict; default-scoped and validation-gated).
                let purgeable =
                    sessions
                        .entry_with_origin(&key)
                        .is_some_and(|(decision, metadata, _)| {
                            !metadata.is_reverse
                                && decision.install_table_domain == domain
                                && decision.install_table_check == check
                                && install_table_purge::install_table_purge_predicate(
                                    forwarding, &key, &decision,
                                )
                        });
                if purgeable {
                    commands::handle_delete_synced(
                        sessions,
                        session_map,
                        forwarding,
                        ha_state,
                        key,
                        now_ns,
                        now_secs,
                        &mut deleted_synced_keys,
                        worker_id,
                    );
                }
            }
            WorkerCommand::EnqueueShapedLocal(req) => {
                // Trivial variant — kept inline (#1346 plan v2 §4.1).
                shaped_tx_requests.push(req);
            }
            WorkerCommand::InstallPptpCall {
                call,
                control,
                learned_ns,
            } => {
                // #7699: learn the association on THIS worker. A collision is
                // refused rather than merged (two calls sharing one handle
                // share one session), and counted so a refusal is not silent.
                if let Err(e) = sessions.pptp_mut().install(call, control, learned_ns) {
                    debug_log!("PPTP association refused: {:?}", e);
                }
            }
            WorkerCommand::ForgetPptpCall(handle) => {
                // #7699: a stale association re-pairs a REUSED 16-bit call id
                // onto a dead handle, so teardown must land on every worker.
                sessions.pptp_mut().remove(handle);
            }
            WorkerCommand::ForgetPptpCallByControl(disconnect) => {
                sessions
                    .pptp_mut()
                    .forget_call_disconnected_by(disconnect);
            }
            WorkerCommand::ForgetPptpControlChannel { control, closed_ns } => {
                // #11053: tear down only the PPTP associations. The control
                // TCP session may still be owned by this worker.
                sessions
                    .pptp_mut()
                    .forget_control_channel_learned_by(control, closed_ns);
            }
            WorkerCommand::VacateAllSharedExactSlots => {
                // Trivial variant — kept inline (#1346 plan v2 §4.1).
                // #941 Work item C: signal the outer poll loop to vacate
                // all shared_exact slots (we don't have BindingWorker
                // access here, so we set the flag and let
                // `worker.rs:818-822` dispatch).
                vacate_all_shared_exact_slots = true;
            }
        }
    }
    // #9720: step the refused-transition debt by the drained slice and
    // dispatch the ops whose position is reached — AFTER the slice. The
    // refused command is newer than the backlog it was refused by (v2's
    // dispatch-ahead ran it first, which installs transitions before older
    // queued mutations); the countdown restores its true FIFO position
    // between pre-transition backlog and post-transition arrivals, bounded
    // by ~1 slice however long the overload lasts. The emptiness below is
    // the drain's own observation from the slice critical section (S3) —
    // never a re-lock — and the debt lock is released before any handler
    // runs (leaf discipline). Scope, apply-level only: on a contended pass
    // the position is unknowable, so debt is left untouched and only the
    // carry flag is reported; the PRODUCTION scheduling (calling apply on
    // debt alone) lives in the worker loop gate, not here (SPARK-F3).
    // #11360 repair positions are advanced while the queue lock is held above,
    // so an importer cannot capture a prefix that the consumer has already
    // drained without its sequence being reflected in the target.
    let transition_debt_pending = if queue_lock_acquired {
        let (ready, pending) =
            worker_queue::take_ready_transition_debt(worker_id, drained, !commands_backlogged);
        for op in ready {
            dispatch_transition_debt_op(
                sessions,
                session_map,
                conntrack_v4_fd,
                conntrack_v6_fd,
                forwarding,
                ha_state,
                dynamic_neighbors,
                op,
                now_ns,
                now_secs,
                &mut cancelled_keys,
                &mut cancelled_keys_seen,
                &mut vacate_all_shared_exact_slots,
            );
        }
        pending
    } else {
        worker_queue::has_transition_debt(worker_id)
    };
    WorkerCommandResults {
        cancelled_keys,
        deleted_synced_keys,
        stale_replay_dropped_keys,
        session_import_repairs,
        exported_sequences,
        session_counter_answers,
        export_owner_rgs,
        export_kick_epoch,
        shaped_tx_requests,
        vacate_all_shared_exact_slots,
        commands_backlogged,
        transition_debt_pending,
        session_import_repair_pending,
    }
}

/// Dispatch one position-ready transition-debt op (the #9720 filter).
///
/// Each RG is filtered against CURRENT HA state with the same `.active`
/// predicate transition detection uses (`forwarding/ha.rs`): a demote RG
/// applies iff its group is not active (absent counts inactive, matching
/// removal-demotes), a refresh RG iff active (absent skipped). A newer
/// transition for the RG — in-band or a superseding debt op — already moved
/// it on, so dispatching the stale op would corrupt post-transition state
/// (parent GPT-2 failback: an unguarded demote flips newly established local
/// origins without any ownership check); the skip is counted per RG (O8) so
/// `DROPPED = applied-late + stale-skipped` stays reconcilable. Filtered
/// debt is consumed, not requeued: the countdown already spent its position.
///
/// Vacate is unconditional: it is idempotent and the next organic publish
/// heals the one-publish-cycle false-zero window (O4 notes vacate does not
/// COMMUTE with publish — the countdown is what keeps it positioned like
/// in-band rather than trailing the drain).
///
#[allow(clippy::too_many_arguments)]
fn dispatch_transition_debt_op(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    op: worker_queue::TransitionDebtOp,
    now_ns: u64,
    now_secs: u64,
    cancelled_keys: &mut Vec<SessionKey>,
    cancelled_keys_seen: &mut rustc_hash::FxHashSet<SessionKey>,
    vacate_all_shared_exact_slots: &mut bool,
) {
    use worker_queue::TransitionDebtKind;
    let rg_is_active = |rg: &i32| ha_state.get(rg).map(|r| r.active).unwrap_or(false);
    match op.kind() {
        TransitionDebtKind::Demote => {
            let surviving: Vec<i32> = op
                .rgs()
                .iter()
                .copied()
                .filter(|rg| !rg_is_active(rg))
                .collect();
            worker_queue::HA_TRANSITION_DEMOTE_STALE_SKIPPED
                .fetch_add((op.rgs().len() - surviving.len()) as u64, Ordering::Relaxed);
            if !surviving.is_empty() {
                commands::handle_demote_owner_rgs(
                    sessions,
                    session_map,
                    conntrack_v4_fd,
                    conntrack_v6_fd,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    surviving,
                    now_ns,
                    now_secs,
                    cancelled_keys,
                    cancelled_keys_seen,
                );
            }
        }
        TransitionDebtKind::Refresh => {
            let surviving: Vec<i32> = op.rgs().iter().copied().filter(rg_is_active).collect();
            worker_queue::HA_TRANSITION_REFRESH_STALE_SKIPPED
                .fetch_add((op.rgs().len() - surviving.len()) as u64, Ordering::Relaxed);
            if !surviving.is_empty() {
                commands::handle_refresh_owner_rgs(
                    sessions,
                    session_map,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    surviving,
                    now_ns,
                    now_secs,
                );
            }
        }
        TransitionDebtKind::Vacate => {
            *vacate_all_shared_exact_slots = true;
        }
    }
}

/// #4800: calls to [`replicate_session_upsert`] (one per new flow), and the
/// total number of live-worker `UpsertSynced` commands those calls attempted.
/// The second is `calls * live sibling count`; the separate worker-queue SHED
/// counter accounts for dead siblings that were intentionally skipped.
pub(crate) static SESSION_REPLICATION_UPSERTS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SESSION_REPLICATION_ENQUEUED: AtomicU64 = AtomicU64::new(0);

/// #4800: sibling worker-queue mutex acquisitions in
/// [`replicate_session_upsert`] that found the queue already held.
///
/// The denominator is `SESSION_REPLICATION_ENQUEUED`, which is incremented
/// once per live sibling IMMEDIATELY BEFORE that sibling's acquisition — so the
/// pair is a ratio over acquisitions actually ATTEMPTED, at every instant and
/// not merely once a call has returned. Dead queues are excluded because their
/// mutexes are not acquired; their skipped legs are counted by SHED_TOTAL.
/// Booking the whole fan-out up front (the pre-fix order) understated
/// contention by the sibling count for any scrape landing mid-call.
pub(crate) static SESSION_REPLICATION_LOCK_CONTENDED: AtomicU64 = AtomicU64::new(0);

/// #4800: sum of the per-call deepest sibling-queue depth observed at
/// replication push time. Divided by `SESSION_REPLICATION_UPSERTS` over the
/// same window this is the MEAN worst-sibling depth per replicated flow —
/// the queue-backlog statistic the analysis layer actually uses.
///
/// This exists because the high-water max below CANNOT be differenced. A
/// process-lifetime `fetch_max` never falls, so across any window
/// `after - before == 0` means either "no backlog" or "a backlog up to the
/// previous all-time high" — ambiguous over the entire useful range — while
/// the absolute value stays elevated forever after one spike. Reading the
/// max as a window value made every cell after the first spike report a
/// replication backlog, which is exactly the site the #2852 Phase-2
/// decision turns on: a systematic bias toward the wrong answer. A SUM is
/// differenceable by construction and carries no history into the next
/// window.
///
/// Contention and depth remain distinct findings: contention says producers
/// collided on the mutex, depth says the consuming worker is not draining as
/// fast as producers enqueue. Different failures, different remedies.
///
/// Accumulated once per call (the max across this call's siblings) rather
/// than once per enqueue, so the cost stays O(1) in the sibling count.
pub(crate) static SESSION_REPLICATION_QUEUE_DEPTH_SUM: AtomicU64 = AtomicU64::new(0);

/// #4800: high-water sibling-queue depth observed at replication push time
/// (monotonic max, never reset).
///
/// OPERATOR GAUGE ONLY — "the deepest this queue has ever been since the
/// helper started". It is deliberately NOT an input to any harness verdict:
/// see `SESSION_REPLICATION_QUEUE_DEPTH_SUM` above for why a lifetime max
/// cannot answer a per-window question. Do not wire it back into an
/// attribution; `newflow_ceiling_analyze.py` has a guard test asserting it
/// cannot produce a culprit.
///
/// Sampled once per call (the max across this call's siblings) rather than
/// once per enqueue, so the cost is O(1) in the sibling count.
pub(crate) static SESSION_REPLICATION_QUEUE_DEPTH_MAX: AtomicU64 = AtomicU64::new(0);

pub(super) fn replicate_session_upsert(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_command_queues: &WorkerCommandQueues,
    entry: &SyncedSessionEntry,
) {
    // #4800: in test builds only, hold the shared side of the counter lock for
    // the whole fan-out, so a reading test excludes this mover without the
    // caller having to opt in. The previous hand-written inventory had already
    // missed two real movers (`coordinator::sync_worker_session_tables` and
    // `promote::maybe_promote_synced_session`).
    //
    // This does NOT make the mover set closed: the `SESSION_REPLICATION_*`
    // statics are `pub(crate)` and any module can bump one directly, and
    // `worker_queue::lock_recover_counting` takes an arbitrary counter. It
    // covers the movers reachable through today's call graph, which is a
    // convention, not an invariant. See `afxdp::counter_test_lock`.
    #[cfg(test)]
    let _counter_guard = crate::afxdp::counter_test_lock::counter_mover_guard();
    let mut replica = None;
    // #4800: two O(1) counter updates per call rather than per sibling.
    SESSION_REPLICATION_UPSERTS.fetch_add(1, Ordering::Relaxed);
    let mut deepest = 0u64;
    for commands in worker_commands {
        // #12192: worker-ID reuse cannot misattribute this queue because
        // `WorkerCommandQueues` resolves the same Arc identity used to pair
        // the queue with this generation's runtime atomics.
        if worker_command_queues.shed_if_dead(commands) {
            continue;
        }
        let replica = replica.get_or_insert_with(|| synced_replica_entry(entry));
        // #4800: count this live sibling's acquisition ATTEMPT immediately
        // before making it, NOT the whole fan-out up front.
        //
        // Pre-booking `worker_commands.len()` here made the contention ratio
        // structurally wrong for any scrape taken mid-call, which is every
        // scrape under load. With 16 sibling queues and queue 0 held, the old
        // order recorded 16 enqueues and 1 contended acquisition and then
        // BLOCKED — a scrape in that window reports 6.25% contention, under the
        // analyzer's 10% threshold, while 100% of the acquisitions actually
        // attempted had blocked. The denominator counted work that had not been
        // tried yet. Incrementing per iteration keeps `contended <= enqueued` a
        // ratio over ATTEMPTED acquisitions at every instant, and leaves the
        // at-rest value identical (every live attempt completes), so the fan-out
        // ratio `enqueued / upserts` is the live sibling multiplier.
        SESSION_REPLICATION_ENQUEUED.fetch_add(1, Ordering::Relaxed);
        // #1807: recover-and-push — `if let Ok` silently DROPPED the
        // UpsertSynced replica for a poisoned worker queue.
        // #4800: ...and count the acquisitions that had to block.
        let mut pending =
            worker_queue::lock_recover_counting(commands, &SESSION_REPLICATION_LOCK_CONTENDED);
        worker_queue::push_bounded(&mut pending, WorkerCommand::UpsertSynced(replica.clone()));
        deepest = deepest.max(pending.len() as u64);
    }
    if deepest != 0 {
        // The SUM is the differenceable statistic the harness reads; the MAX
        // is the operator's all-time high-water and is never a verdict input.
        SESSION_REPLICATION_QUEUE_DEPTH_SUM.fetch_add(deepest, Ordering::Relaxed);
        SESSION_REPLICATION_QUEUE_DEPTH_MAX.fetch_max(deepest, Ordering::Relaxed);
    }
}

/// #8114 item 4: a `DeleteSynced` a sibling worker's queue REFUSED, because it
/// was already at `MAX_PENDING_WORKER_COMMANDS`.
///
/// Counted separately from `WORKER_COMMAND_QUEUE_DROPS` (which counts every
/// refused command of any kind) because the consequences of losing a DELETE are
/// specific: the sibling keeps its local session entry and flow-cache slot for a
/// session that no longer exists, AND keeps its NAT holder bit, so the
/// reservation is held for the life of the allocator.
pub(crate) static SESSION_DELETE_REPLICA_DROPPED: AtomicU64 = AtomicU64::new(0);

/// #9048: a peer `DeleteSynced` REFUSED because the key named a live session
/// this node created itself and is actively forwarding for.
///
/// Non-zero means the cluster is, or recently was, DUAL-PRIMARY for some
/// redundancy group: the delta emitter is gated on `IsPrimaryForRGFn`, so in
/// normal operation exactly one node emits deletes and the receiver's entries
/// at those keys carry a peer-synced origin, leaving the guard inert. A
/// climbing count is therefore a split-brain indicator, not a tuning knob —
/// and it is deliberately a COUNTER rather than a log line, because the
/// condition that produces it produces one per closing flow.
///
/// The refusal is the conservative side of the trade: a session that lingers
/// until it ages out, against a live flow torn down mid-transfer.
pub(crate) static PEER_DELETE_REFUSED_LOCAL_OWNED: AtomicU64 = AtomicU64::new(0);

/// #8114 item 4: refused deletes whose owning worker was IDENTIFIED and whose
/// NAT teardown was therefore run on its behalf.
///
/// The difference `SESSION_DELETE_REPLICA_DROPPED - SESSION_DELETE_REPLICA_DROP_REPAIRED`
/// is the number of refused deletes that could not be attributed to a worker id
/// — a caller that had no `worker_commands_by_id` to resolve against. It is
/// deliberately a SECOND counter rather than a conditional increment of the
/// first: a single number could not distinguish "no drops" from "drops nobody
/// repaired", and those have opposite remediations.
pub(crate) static SESSION_DELETE_REPLICA_DROP_REPAIRED: AtomicU64 = AtomicU64::new(0);

/// #8586: per-worker epoch, bumped when a cross-worker `DeleteSynced` replica
/// for THAT worker was refused by its full queue.
///
/// It is the out-of-band signal the refused worker needs, and it has to be
/// out-of-band by construction: the thing that must reach it cannot travel
/// through the queue that is full. One relaxed load per worker per loop pass on
/// the read side, one relaxed increment per refusal on the write side.
///
/// WHY IT COUNTS DELETES AND NOT QUEUE PRESSURE. Measured on
/// `loss:xpf-userspace-fw0` (#8586): ordinary session ESTABLISHMENT pins the
/// queue at the 4096 cap and discards 85,668 commands over 32,768 creates —
/// and ZERO of them are deletes. What is lost there is `UpsertSynced` replicas,
/// whose content the shared map still holds. A trigger keyed on queue depth, or
/// on `WORKER_COMMAND_QUEUE_DROPS`, would therefore fire continuously through
/// normal traffic and reconcile nothing. The harmful loss is confined to a
/// revocation burst or an RG activation: one `clear security flow session` over
/// 32,770 entries refused 30,786 delete replicas, and the two conditions come
/// apart cleanly enough to key on.
///
/// Indexed by worker id, bounded by `MAX_NAT_HOLDER_WORKERS` — the same ceiling
/// `replan_bindings` refuses to mint past, so a worker id is always in range.
/// A refusal whose worker id could NOT be resolved bumps nothing: there is no
/// worker to name. Those are the `SESSION_DELETE_REPLICA_DROPPED -
/// SESSION_DELETE_REPLICA_DROP_REPAIRED` remainder, measured at 0 across 30,786
/// refusals.
pub(crate) static SESSION_DELETE_DROP_EPOCH: [AtomicU64;
    crate::nat::MAX_NAT_HOLDER_WORKERS as usize] =
    [const { AtomicU64::new(0) }; crate::nat::MAX_NAT_HOLDER_WORKERS as usize];

/// #8586: read a worker's delete-drop epoch. Out of range reads 0 (an id past
/// the planner's own ceiling cannot have been bumped either, so the pair is
/// consistent and a reconcile is never raised for a worker that cannot exist).
pub(crate) fn session_delete_drop_epoch(worker_id: u32) -> u64 {
    SESSION_DELETE_DROP_EPOCH
        .get(worker_id as usize)
        .map(|e| e.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// #8114 item 4: what one `replicate_session_delete_repairing` fan-out did,
/// per call.
///
/// `dropped` counts sibling queues that REFUSED the delete; `repaired` counts
/// the subset of those whose worker id resolved, so the NAT teardown ran on
/// their behalf. `dropped - repaired` is the unattributable remainder — a caller
/// with no id map to resolve against. Two fields rather than one because a
/// single number cannot distinguish "no drops" from "drops nobody repaired", and
/// those have opposite remediations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct DeleteReplicationOutcome {
    pub(super) dropped: u32,
    pub(super) repaired: u32,
}

/// Resolve a worker command queue to the worker id that owns it.
///
/// By `Arc` IDENTITY, not by position: `peer_worker_commands` is built in
/// `reconcile/bringup.rs` as
/// `.filter(|(id, _)| **id != worker_id).map(|(_, queue)| queue.clone())`, so the
/// ids are gone by the time the fan-out sees the slice, and its ORDER relative
/// to the id-keyed map depends on which worker is excluded. Asking the map
/// "which id is THIS allocation?" cannot desynchronise the way a parallel
/// `&[u32]` would — the two structures hold the same `Arc`s, not the same facts
/// written down twice.
///
/// `None` when the caller passed a map that does not contain the queue, which is
/// the case for fixtures that do not exercise the repair. That is a no-op, not a
/// wrong repair.
fn worker_id_for_command_queue(
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    queue: &Arc<Mutex<VecDeque<WorkerCommand>>>,
) -> Option<u32> {
    worker_commands_by_id
        .iter()
        .find(|(_, candidate)| Arc::ptr_eq(candidate, queue))
        .map(|(id, _)| *id)
}

pub(super) fn replicate_session_delete(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    key: &SessionKey,
) {
    for commands in worker_commands {
        // #1807: recover-and-push — `if let Ok` silently DROPPED the
        // DeleteSynced replica for a poisoned worker queue.
        let mut pending = worker_queue::lock_recover(commands);
        if !worker_queue::push_bounded(&mut pending, WorkerCommand::DeleteSynced(key.clone())) {
            // #8114 item 4: still unrepaired on this path — see
            // `replicate_session_delete_repairing`. Counted so the drop is not
            // silent even where it cannot be repaired.
            SESSION_DELETE_REPLICA_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// #9752: fan out a conditional purge delete, PLAIN (never repairing). A
/// refused conditional is safe without repair: had the recipient held a
/// purge-worthy entry it re-derives the purge itself (flag on its own
/// terminal observations, or idle age-out), and had it held a valid one
/// the repair would have freed a LIVE port (Codex-r4-F4). Drops still bump
/// the shared counter so they are never silent.
pub(super) fn replicate_purge_delete(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    key: &SessionKey,
    domain: u32,
    check: u32,
) {
    for commands in worker_commands {
        let mut pending = worker_queue::lock_recover(commands);
        if !worker_queue::push_bounded(
            &mut pending,
            WorkerCommand::DeleteSyncedIfTableUnknown {
                key: key.clone(),
                domain,
                check,
            },
        ) {
            SESSION_DELETE_REPLICA_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// #8114 item 4: `replicate_session_delete`, plus the NAT teardown a sibling
/// worker will now never run because its queue refused the `DeleteSynced`.
///
/// The drop is not a missed optimisation. `handle_delete_synced` is what a
/// worker does with the command, and it releases that worker's source-NAT and
/// NAT64 holder bits; the port is freed by whichever worker drops the LAST bit.
/// A worker that never receives the command never drops its bit, so the
/// reservation is held for the life of the allocator — the same stranding
/// `Coordinator::delete_synced_session_gen` repairs on the control-plane side
/// (#6979 F4, whose probe recorded "queue-drop delta 1, pool port still
/// occupied, `dead` false, dead-worker sweep freed 0").
///
/// WHY RELEASING ON ITS BEHALF CANNOT OVER-RELEASE, which is the direction of
/// error that would matter: the command was REFUSED, so that worker will never
/// run this teardown itself, and `release_flow` no-ops unless the allocator's
/// `live_by_flow[flow].translated` equals this exact tuple — so a worker whose
/// own `UpsertSynced` is still queued (no reservation taken yet) is untouched.
/// The rule at `PortAllocator::drop_holder_locked` is satisfied: this clears the
/// bit of a worker that provably cannot forward this flow again. It is also why
/// "just release for every worker id" is NOT a substitute for resolving the id —
/// that would clear the bit of a worker still forwarding the flow, and its port
/// could then be handed to another.
///
/// NOT REPAIRED HERE, deliberately, and it is the half the issue names first:
/// the sibling also never deletes its LOCAL session-table entry or invalidates
/// its flow-cache slots, so it can keep serving the revoked session until the
/// entry ages out. Neither is reachable from this thread — both live behind that
/// worker's `&mut SessionTable` and its own per-binding caches — and the signal
/// that would have to reach it cannot travel through the queue that is full. The
/// NAT reservation is the part with no other owner, so it is the part repaired.
///
/// Returns a PER-CALL [`DeleteReplicationOutcome`] as well as bumping the
/// process-wide counters. The counters are the operator signal; the return
/// value is what a cell can assert on without racing every other test in the
/// binary, which the globals cannot offer (they are shared across the parallel
/// test threads, so `before + 1` is a flake waiting for a busy run).
#[allow(clippy::too_many_arguments)]
pub(super) fn replicate_session_delete_repairing(
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
) -> DeleteReplicationOutcome {
    let mut outcome = DeleteReplicationOutcome::default();
    for commands in peer_worker_commands {
        let mut pending = worker_queue::lock_recover(commands);
        let queued =
            worker_queue::push_bounded(&mut pending, WorkerCommand::DeleteSynced(key.clone()));
        // Release the command queue BEFORE touching allocator mutexes: the two
        // are unrelated locks and holding both would invent an ordering, which
        // is the lock-graph change a green suite cannot see.
        drop(pending);
        if queued {
            continue;
        }
        SESSION_DELETE_REPLICA_DROPPED.fetch_add(1, Ordering::Relaxed);
        outcome.dropped += 1;
        let Some(worker_id) = worker_id_for_command_queue(worker_commands_by_id, commands) else {
            continue;
        };
        SESSION_DELETE_REPLICA_DROP_REPAIRED.fetch_add(1, Ordering::Relaxed);
        outcome.repaired += 1;
        // #8586: tell the refused worker. Its local session entry and its
        // flow-cache slots for this key are the half #8576 could not repair
        // from here — they live behind that worker's own `&mut SessionTable`
        // and per-binding caches — so it has to reconcile them itself, and the
        // signal cannot go through the queue that just refused the command.
        if let Some(epoch) = SESSION_DELETE_DROP_EPOCH.get(worker_id as usize) {
            epoch.fetch_add(1, Ordering::Relaxed);
        }
        // Byte-for-byte the two releases `handle_delete_synced` would have run,
        // with that worker's id as the holder, so the mask empties on the same
        // last-release rule and the port is returned exactly once.
        release_source_nat_allocation_for_worker(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            key,
            nat,
            is_reverse,
            now_ns,
            worker_id,
        );
        crate::nat64::release_nat64_allocation_for_worker(
            &forwarding.nat64,
            key,
            nat,
            is_reverse,
            now_ns,
            worker_id,
        );
    }
    outcome
}

/// Stale-ordinary-close twin of [`replicate_session_delete_repairing`]:
/// siblings delete only when the forward's live identity still matches
/// the captured one, and the carried companion goes with it (same
/// forward-match gate as the scoped HA path — no companion identity is
/// capturable from a close delta). Drop repair mirrors the unconditional
/// twin keystroke for keystroke (exact-keyed releases + epoch signal).
#[allow(clippy::too_many_arguments)]
pub(super) fn replicate_session_delete_conditional(
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    forwarding: &ForwardingState,
    key: &SessionKey,
    nat: NatDecision,
    is_reverse: bool,
    now_ns: u64,
    expected_id: u64,
    companion: Option<SessionKey>,
) -> DeleteReplicationOutcome {
    let mut outcome = DeleteReplicationOutcome::default();
    for commands in peer_worker_commands {
        let mut pending = worker_queue::lock_recover(commands);
        let queued = worker_queue::push_bounded(
            &mut pending,
            WorkerCommand::DeleteSyncedConditional {
                key: key.clone(),
                expected_id,
                companion: companion.clone(),
            },
        );
        drop(pending);
        if queued {
            continue;
        }
        SESSION_DELETE_REPLICA_DROPPED.fetch_add(1, Ordering::Relaxed);
        outcome.dropped += 1;
        let Some(worker_id) = worker_id_for_command_queue(worker_commands_by_id, commands) else {
            continue;
        };
        SESSION_DELETE_REPLICA_DROP_REPAIRED.fetch_add(1, Ordering::Relaxed);
        outcome.repaired += 1;
        if let Some(epoch) = SESSION_DELETE_DROP_EPOCH.get(worker_id as usize) {
            epoch.fetch_add(1, Ordering::Relaxed);
        }
        release_source_nat_allocation_for_worker(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            key,
            nat,
            is_reverse,
            now_ns,
            worker_id,
        );
        crate::nat64::release_nat64_allocation_for_worker(
            &forwarding.nat64,
            key,
            nat,
            is_reverse,
            now_ns,
            worker_id,
        );
    }
    outcome
}

/// #8586: drop this worker's LOCAL entries for peer-synced sessions that shared
/// authority no longer holds, and hand their keys back for flow-cache eviction.
///
/// This is the half of a refused cross-worker `DeleteSynced` that #8576 could
/// not repair from the DELETING worker: that worker released the refused
/// worker's NAT holder bit on its behalf, but the refused worker's own session
/// entry and per-binding flow-cache slots live behind its `&mut SessionTable`
/// and are reachable only from its own loop. The signal that it must run this
/// cannot travel through the queue that refused the command, which is why the
/// trigger is the out-of-band `SESSION_DELETE_DROP_EPOCH`.
///
/// SCOPED BY `SessionOrigin::is_peer_synced()`, and the exclusions are the
/// safety property rather than a detail:
///
/// - `SharedPromote` is EXCLUDED, and it is the one a reader would expect to be
///   in. It is synced-DERIVED but no longer peer-AUTHORITATIVE: it is the origin
///   an entry receives after local traffic has promoted it, so this node owns it
///   and shared authority is not the arbiter of whether it should exist.
///   Reconciling it away would delete a live local session. (`loop_body`'s
///   "synced-derived, never create-counted" arm DOES include `SharedPromote`;
///   it asks a different question and is correct for it. Using that
///   classification here would be the bug.)
/// - `FabricPuntSeed` and `MissingNeighborSeed` are transient-local by
///   construction — never HA-exported, never Open-delta'd — so they are live
///   local sessions that are ABSENT from the shared map by design. A naive
///   "drop what the shared map does not have" sweep deletes them on its first
///   pass. That is the worse-failure-mode #8586 declined to build against an
///   unestablished premise, and `is_peer_synced()` excludes them.
///
/// The worker-loop path uses [`DeleteDropSweep::step_with_nat`], which also
/// drops this worker's source-NAT and NAT64 holder bits before deleting the
/// local entry (#10288). That release is holder-aware and idempotent: for the
/// refused-delete case #8576 already cleared the bit, while an accepted
/// DeleteSynced still queued needs this sweep to close the window. This
/// whole-table behavioural wrapper remains steering-only because its callers
/// intentionally model the #8586 table/cache half without forwarding state.
///
/// The shared-map lock is held only across the membership FILTER, not across
/// the table walk: the walk clones candidate keys first. Sibling workers take
/// that same lock on their packet path, and a full-table walk under it would
/// stall them for the length of this worker's session table.
/// Run the delete-drop reconcile to completion.
///
/// #9327: the worker loop no longer calls this — it steps a [`DeleteDropSweep`]
/// across passes so no single pass exceeds the ring-fill budget. This wrapper
/// is the whole-table semantics in one call, which is what the behavioural
/// cells (#8586: which ORIGINS are swept) want to assert without modelling the
/// pacing. Keeping the semantics and the pacing testable separately is the
/// point: a cell that had to drive the cursor to check an origin rule would be
/// asserting two things at once.
pub(in crate::afxdp) fn reconcile_peer_synced_against_shared(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    session_map: SteeringMap<'_>,
    evicted_keys: &mut Vec<SessionKey>,
) -> usize {
    let mut sweep = DeleteDropSweep::default();
    sweep.arm();
    let mut total = 0;
    while sweep.is_running() {
        total += sweep.step(sessions, shared_sessions, session_map, evicted_keys);
    }
    total
}

pub(super) fn should_teardown_tcp_rst(_meta: UserspaceDpMeta, _flow: Option<&SessionFlow>) -> bool {
    // Do not immediately delete live sessions on an observed TCP RST.
    //
    // On the current HA userspace dataplane, stray or misclassified reply-side
    // RSTs can appear while the real flow is still active. Immediate teardown
    // removes the pinned live-session keys from USERSPACE_SESSIONS, which then
    // causes userspace-xdp to stop redirecting valid reply traffic and the
    // kernel to emit follow-on RSTs that collapse the connection entirely.
    //
    // The session table already marks TCP entries as closing when FIN/RST is
    // seen and ages them on the shorter TCP_CLOSING timeout. Rely on that
    // path for now until RST provenance is made trustworthy again.
    false
}

pub(super) fn teardown_tcp_rst_flow(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forward_key: &SessionKey,
    nat: NatDecision,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    let reverse_key = reverse_session_key(forward_key, nat);
    sessions.delete(forward_key);
    sessions.delete(&reverse_key);
    delete_live_session_entry(
        current.bpf_maps.session_map.handle(),
        forward_key,
        nat,
        false,
    );
    delete_live_session_entry(
        current.bpf_maps.session_map.handle(),
        &reverse_key,
        nat,
        true,
    );
    delete_bpf_conntrack_entry(
        current.bpf_maps.conntrack_v4_fd,
        current.bpf_maps.conntrack_v6_fd,
        forward_key,
    );
    delete_bpf_conntrack_entry(
        current.bpf_maps.conntrack_v4_fd,
        current.bpf_maps.conntrack_v6_fd,
        &reverse_key,
    );
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        forward_key,
    );
    // #9560 round 3: release the coordinator's claim with the shared authority it
    // stood for.
    release_coordinator_session_rows(current.bpf_maps.session_map.handle(), forward_key);
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        &reverse_key,
    );
    // #9560 round 3: and for the reverse half's own shared entry.
    release_coordinator_session_rows(current.bpf_maps.session_map.handle(), &reverse_key);
    replicate_session_delete(peer_worker_commands, forward_key);
    replicate_session_delete(peer_worker_commands, &reverse_key);
    cancel_pending_forwards(current, pending_forwards, forward_key, &reverse_key);
    cancel_queued_flow(
        left,
        current,
        right,
        forward_key,
        &reverse_key,
        shared_recycles,
    );
}

pub(super) fn cancel_queued_flow(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    for binding in left.iter_mut() {
        cancel_queued_flow_on_binding(binding, forward_key, reverse_key, Some(shared_recycles));
    }
    cancel_queued_flow_on_binding(current, forward_key, reverse_key, Some(shared_recycles));
    for binding in right.iter_mut() {
        cancel_queued_flow_on_binding(binding, forward_key, reverse_key, Some(shared_recycles));
    }
    route_cancelled_shared_recycles(left, current, right, shared_recycles);
}

fn route_cancelled_shared_recycles(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    shared_recycles: &mut Vec<(u32, u64)>,
) {
    if shared_recycles.is_empty() {
        return;
    }
    // F-149 (#9904): same single-region backstop as the dispatch paths, with
    // the same bounded one-line-per-drain logging (this site previously logged
    // per drop inside the loop — a spam vector on a stale-slot flood).
    let backstop = split_is_single_region(left, current, right);
    let mut dropped = 0u64;
    let mut rescued = 0u64;
    let mut first_drop = None;
    let mut first_rescue = None;
    for (slot, offset) in shared_recycles.drain(..) {
        if let Some(binding) = left
            .iter_mut()
            .chain(core::iter::once(&mut *current))
            .chain(right.iter_mut())
            .find(|binding| binding.slot == slot)
        {
            binding.tx_pipeline.pending_fill_frames.push_back(offset);
        } else if backstop {
            // Same-region per the premise on `split_is_single_region`:
            // kernel-masked, bounds-checked, growth-bounded. See note.
            current.tx_pipeline.pending_fill_frames.push_back(offset);
            first_rescue.get_or_insert((slot, offset));
            rescued = rescued.saturating_add(1);
        } else {
            first_drop.get_or_insert((slot, offset));
            dropped = dropped.saturating_add(1);
        }
    }
    log_shared_recycle_unknown_slot_drops(dropped, first_drop);
    log_shared_recycle_unknown_slot_rescues(rescued, first_rescue);
    record_shared_recycle_unknown_slot_drops(Some(&current.live), dropped);
    record_shared_recycle_unknown_slot_rescues(Some(&current.live), rescued);
}

pub(super) fn cancel_queued_flow_on_binding(
    binding: &mut BindingWorker,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
    shared_recycles: Option<&mut Vec<(u32, u64)>>,
) {
    let mut shared_recycles = shared_recycles;
    let mut kept_local = VecDeque::with_capacity(binding.tx_pipeline.pending_tx_local.len());
    while let Some(req) = binding.tx_pipeline.pending_tx_local.pop_front() {
        if tx_request_matches_flow(&req, forward_key, reverse_key) {
            continue;
        }
        kept_local.push_back(req);
    }
    binding.tx_pipeline.pending_tx_local = kept_local;

    let mut kept_prepared = VecDeque::with_capacity(binding.tx_pipeline.pending_tx_prepared.len());
    while let Some(req) = binding.tx_pipeline.pending_tx_prepared.pop_front() {
        if prepared_request_matches_flow(&req, forward_key, reverse_key) {
            recycle_cancelled_prepared(binding, &req, shared_recycles.as_deref_mut());
            continue;
        }
        kept_prepared.push_back(req);
    }
    binding.tx_pipeline.pending_tx_prepared = kept_prepared;

    // #706: the cross-worker redirect inbox (`binding.live.pending_tx`) is
    // now a lock-free MPSC ring (`MpscInbox`). In-place filtering from an
    // arbitrary thread is not safe on that structure — only the owner
    // worker may drain it. We accept that packets already sitting in the
    // redirect inbox for a now-canceled flow will drain out on the next
    // owner poll and hit the wire; the peer already saw a RST, so the
    // extra late packets are ignored (or provoke a benign RST-for-RST
    // response) rather than causing protocol harm. The worker-owned
    // `pending_tx_local` and `pending_tx_prepared` queues above are still
    // filtered because they are never touched by another thread.

    update_binding_debug_state(binding);
}

pub(super) fn cancel_pending_forwards(
    binding: &mut BindingWorker,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) {
    let mut kept = Vec::with_capacity(pending_forwards.len());
    for req in pending_forwards.drain(..) {
        if pending_forward_matches_flow(&req, forward_key, reverse_key) {
            binding
                .tx_pipeline
                .pending_fill_frames
                .push_back(req.desc.addr);
            continue;
        }
        kept.push(req);
    }
    *pending_forwards = kept;
}

pub(super) fn recycle_cancelled_prepared(
    binding: &mut BindingWorker,
    req: &PreparedTxRequest,
    shared_recycles: Option<&mut Vec<(u32, u64)>>,
) {
    recycle_cancelled_prepared_offset_with_shared(
        &mut binding.tx_pipeline.free_tx_frames,
        &mut binding.tx_pipeline.pending_fill_frames,
        shared_recycles,
        binding.slot,
        req.recycle,
        req.offset,
    );
}

pub(super) fn tx_request_matches_flow(
    req: &TxRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

pub(super) fn prepared_request_matches_flow(
    req: &PreparedTxRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

pub(super) fn pending_forward_matches_flow(
    req: &PendingForwardRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

fn materialize_shared_session_hit(
    sessions: &mut SessionTable,
    resolved: &mut ResolvedSessionLookup,
    forwarding: &ForwardingState,
    now_ns: u64,
    tcp_flags: u8,
) -> (SessionLookup, bool) {
    if let Some(shared) = resolved.shared_entry.take() {
        // #10612 (N2): fence stale-zone shared hits at materialize ingress.
        // A shared-transient stale row (import fail-open linger racing
        // validation) must materialize as a MISS, not install into the
        // worker table (the later arm-drop would not remove it).
        if synced_entry_is_stale_replay(shared.origin, &shared.metadata, forwarding) {
            note_stale_replay_fence_drop();
            return (resolved.lookup.clone(), false);
        }
        let mut replica = synced_replica_entry(&shared);
        // A zero token carries no leak provenance and is recomputed locally
        // for peer-synced rows. A nonzero token was computed before this
        // shared row was published (and survives demotion), so preserve it as
        // revocation evidence.
        if shared.origin.is_peer_synced() && replica.leak_incarnation == 0 {
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
        let materialized = sessions.upsert_synced_with_origin(
            SessionInstall {
                key: replica.key.clone(),
                decision: replica.decision,
                metadata: replica.metadata.clone(),
                origin: shared.origin.materialized_shared_hit_origin(),
                now_ns,
                protocol: replica.protocol,
                tcp_flags,
                // #5212: a reactive materialize of a shared-map hit inherits the
                // shared entry's id — the peer's id for a synced session (so the
                // eventual close correlates), 0 for a local entry (fresh alloc).
                session_id: replica.session_id,
                // #9412: a materialized shared hit keeps the synced close class, so
                // a closing peer copy is not reset to the established window by the
                // worker that happens to see its next packet.
                tcp_close_class: replica.tcp_close_class,
                tcp_handshake_state: replica.tcp_handshake_state,
                source_nat_static: replica.source_nat_static,
            },
            false,
        );
        // A refused shared repair must not mutate the incumbent local row's
        // leak provenance. The stamp is evidence for the materialized replica
        // only; failed clobber attempts return install_failed instead.
        if materialized
            && let Some(incarnation) =
                (replica.leak_incarnation != 0).then_some(replica.leak_incarnation)
        {
            sessions.stamp_leak_incarnation(&replica.key, incarnation);
        }
        return (
            SessionLookup {
                decision: replica.decision,
                metadata: replica.metadata,
                forwarding_generation: ForwardingGenerationStamp::default(),
                aux: SessionLookupAux {
                    session_id: replica.session_id,
                    source_nat_static: replica.source_nat_static,
                    leak_incarnation: replica.leak_incarnation,
                },
            },
            !materialized,
        );
    }
    (resolved.lookup.clone(), false)
}

// Test and non-worker callers retain the no-conntrack transition behavior.
// The production poll path uses the `_with_conntrack` variant so helper
// promote/demote transitions can invalidate only the origin bit in the mirror.
pub(super) fn resolve_flow_session_decision(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    flow: &SessionFlow,
    now_ns: u64,
    now_secs: u64,
    protocol: u8,
    tcp_flags: u8,
    ingress_ifindex: i32,
    ingress_vlan_id: u16,
    fabric_ingress: bool,
    ha_startup_grace_until_secs: u64,
    worker_id: u32,
    verdict: SessionHitVerdict,
) -> Option<ResolvedFlowSessionDecision> {
    let mut resolved = resolve_flow_session_decision_with_conntrack(
        sessions,
        session_map,
        -1,
        -1,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        peer_worker_commands,
        empty_worker_commands_by_id(),
        forwarding,
        ha_state,
        dynamic_neighbors,
        flow,
        now_ns,
        now_secs,
        protocol,
        tcp_flags,
        ingress_ifindex,
        ingress_vlan_id,
        fabric_ingress,
        fabric_ingress,
        ha_startup_grace_until_secs,
        worker_id,
        None,
    )?;
    maybe_promote_synced_session_with_conntrack(
        sessions,
        session_map,
        -1,
        -1,
        SharedSessionRefs {
            sessions: shared_sessions,
            nat_sessions: shared_nat_sessions,
            forward_wire_sessions: shared_forward_wire_sessions,
            owner_rg_indexes: shared_owner_rg_indexes,
        },
        peer_worker_commands,
        empty_worker_commands_by_id(),
        forwarding,
        now_ns,
        tcp_flags,
        worker_id,
        verdict,
        &mut resolved,
    );
    if verdict == SessionHitVerdict::Owner
        && let Some(revalidation) = resolved.deferred_forwarding_revalidation.take()
    {
        if revalidation.invalidate_policy_revalidation {
            sessions.invalidate_policy_revalidation(&resolved.key);
        }
        sessions.revalidate_forwarding_resolution(
            &resolved.key,
            revalidation.resolution,
            revalidation.owner_rg_id,
        );
        if let Some(owner_rg_id) = revalidation.owner_rg_id {
            resolved.metadata.owner_rg_id = owner_rg_id;
        }
    }

    Some(resolved)
}

/// Materialize a shared entry only after the packet's Owner verdict.
pub(in crate::afxdp::session_glue) fn apply_deferred_shared_materialization(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    now_ns: u64,
    tcp_flags: u8,
    verdict: SessionHitVerdict,
    resolved: &mut ResolvedFlowSessionDecision,
) {
    if verdict != SessionHitVerdict::Owner {
        return;
    }
    let Some(entry) = resolved
        .deferred_shared_materialization
        .take()
        .map(|deferred| deferred.entry)
    else {
        return;
    };
    let mut hit = ResolvedSessionLookup::shared(entry);
    let (_, install_failed) =
        materialize_shared_session_hit(sessions, &mut hit, forwarding, now_ns, tcp_flags);
    resolved.install_failed = install_failed;
    if resolved.session_id == 0 && !install_failed {
        resolved.session_id = sessions.session_id_for(&resolved.key);
    }
    if install_failed {
        resolved.deferred_synced_promotion = None;
    }
}

pub(super) fn resolve_flow_session_decision_with_conntrack(
    sessions: &mut SessionTable,
    session_map: SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_commands_by_id: &WorkerCommandQueues,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    flow: &SessionFlow,
    now_ns: u64,
    now_secs: u64,
    protocol: u8,
    tcp_flags: u8,
    ingress_ifindex: i32,
    // #9383: the arrival frame's VLAN id, needed ONLY to resolve
    // `ingress_ifindex` (a physical bind port) to the LOGICAL unit ifindex the
    // zone ledger is keyed by. A caller with no VLAN context passes 0, which
    // resolves logical == physical for every untagged port.
    ingress_vlan_id: u16,
    // `fabric_ingress` is the validated stamp/overlay semantic used by
    // session policy; `fabric_link_ingress` is the physical parent-or-overlay
    // arrival semantic used by the anti-loop redirect guard.
    fabric_ingress: bool,
    fabric_link_ingress: bool,
    ha_startup_grace_until_secs: u64,
    // #6211 F2: THIS worker's id, threaded from `WorkerLaunchPlan::worker_id`
    // in the worker loop. A peer-synced reservation is held by every worker, so
    // a release must drop THIS worker's bit rather than free the port outright.
    worker_id: u32,
    // Only the unique unstamped-fabric reverse-NAT exception supplies this.
    prevalidated_forward_nat_match: Option<crate::session::ForwardSessionMatch>,
) -> Option<ResolvedFlowSessionDecision> {
    if !crate::session::PMechSessionDirectory::global()
        .probe_packet_key(&flow.forward_key)
        .is_fallthrough()
    {
        return None;
    }
    // Bundle the four shared-session refs once per call. `SharedSessionRefs`
    // is `#[derive(Copy)]`, so the three downstream uses below
    // (purge_translated_synced_hit + 2× maybe_promote_synced_session) each
    // get a free by-value copy — structurally same codegen as the
    // explicit-argument form (4 pointer-sized fields, no Drop). cargo-asm
    // 0.1.16 cannot parse this codebase's symbols, so the empirical gate
    // is the smoke-plus-test-failover pass on the loss userspace cluster.
    let shared = SharedSessionRefs {
        sessions: shared_sessions,
        nat_sessions: shared_nat_sessions,
        forward_wire_sessions: shared_forward_wire_sessions,
        owner_rg_indexes: shared_owner_rg_indexes,
    };
    if let Some(mut hit) = lookup_session_across_scopes_with_shared(
        sessions,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        &flow.forward_key,
        now_ns,
        tcp_flags,
    ) {
        let hit_origin = hit.origin;
        let poison_key = hit
            .shared_entry
            .as_ref()
            .map(|entry| (&entry.key, entry.decision, &entry.metadata, entry.origin))
            .or_else(|| {
                Some((
                    hit.key.as_ref(&flow.forward_key),
                    hit.lookup.decision,
                    &hit.lookup.metadata,
                    hit_origin,
                ))
            });
        let shared_was_present = hit.shared_entry.is_some();
        // Preserve the shared session incarnation before materialization takes
        // its entry out of `hit`; local-only hits read it from the table below.
        let shared_session_id = hit.shared_entry.as_ref().map(|entry| entry.session_id);
        let shared_leak_incarnation = hit.shared_entry.as_ref().map(|entry| entry.leak_incarnation);
        let source_nat_static = hit
            .shared_entry
            .as_ref()
            .map(|entry| entry.source_nat_static)
            .unwrap_or(hit.lookup.aux.source_nat_static);
        let keep_transient = poison_key.is_some_and(|(key, decision, metadata, origin)| {
            should_keep_synced_hit_transient(ha_state, now_secs, key, decision, metadata, origin)
        });
        let session_id_before_purge = shared_session_id
            .filter(|session_id| *session_id != 0)
            .unwrap_or_else(|| {
                if shared_was_present {
                    0
                } else {
                    hit.lookup.aux.session_id
                }
            });
        let source_nat_validation_key = if keep_transient {
            shared_source_nat_original_key(
                shared.forward_wire_sessions,
                &flow.forward_key,
                hit.key.as_ref(&flow.forward_key),
                hit.lookup.decision,
                &hit.lookup.metadata,
                hit_origin,
                source_nat_static,
                session_id_before_purge,
            )
        } else {
            None
        };
        let deferred_synced_purge = if keep_transient {
            poison_key.map(|(key, decision, metadata, origin)| DeferredSyncedPurge {
                key: key.clone(),
                decision,
                metadata: metadata.clone(),
                origin,
            })
        } else {
            None
        };
        let deferred_shared_materialization = if keep_transient {
            None
        } else {
            hit.shared_entry
                .clone()
                .map(|entry| DeferredSharedMaterialization { entry })
        };
        let resolved = hit.lookup.clone();
        let resolved_key = hit.key.as_ref(&flow.forward_key);
        let forwarding_stale =
            sessions.forwarding_resolution_is_stale(resolved.forwarding_generation);
        let session_id = shared_session_id
            .filter(|session_id| *session_id != 0)
            .unwrap_or(session_id_before_purge);
        let previous_policy_to_zone_id = forwarding_stale.then(|| {
            if resolved.decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
                resolved.metadata.egress_zone
            } else {
                forwarding.egress_zone_id(resolved.decision.resolution.egress_ifindex)
            }
        });
        let mut decision = resolved.decision;
        let resolution_target = resolution_target_for_session(flow, decision);
        let leak_incarnation = shared_leak_incarnation
            .filter(|incarnation| *incarnation != 0)
            .or((hit.lookup.aux.leak_incarnation != 0)
                .then_some(hit.lookup.aux.leak_incarnation));
        let leak_revoked = leak_incarnation.is_some_and(|incarnation| {
            !super::forwarding::leak_incarnation_is_live(forwarding, resolution_target, incarnation)
        });
        let looked_up_resolution = if let Some(stamped_incarnation) =
            leak_incarnation.filter(|_| leak_revoked)
        {
            // #9951: a revoked provenance stamp bypasses every cached arm,
            // including the synced-session fallback (which intentionally
            // keeps cached fallback for ordinary peer imports).
            let refreshed = lookup_forwarding_resolution_for_session_without_cache(
                forwarding,
                dynamic_neighbors,
                flow,
                decision,
            )
            .resolution;
            let current_incarnation =
                leak_incarnation_for_session(forwarding, decision, resolution_target);
            if current_incarnation.is_some_and(|current| current != stamped_incarnation) {
                super::no_route_resolution(None)
            } else {
                refreshed
            }
        } else if forwarding_stale {
            lookup_forwarding_resolution_for_session_without_cache(
                forwarding,
                dynamic_neighbors,
                flow,
                decision,
            )
            .resolution
        } else if hit_origin.is_peer_synced() {
            lookup_forwarding_resolution_for_synced_session(
                forwarding,
                dynamic_neighbors,
                flow,
                decision,
            )
            .resolution
        } else {
            lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision)
                .resolution
        };
        let looked_up_resolution = super::prefer_local_forward_candidate_for_fabric_ingress(
            forwarding,
            ha_state,
            dynamic_neighbors,
            now_secs,
            fabric_ingress,
            resolution_target,
            install_table_name_for_session(forwarding, decision, resolution_target),
            looked_up_resolution,
        );
        let enforced_resolution = enforce_session_ha_resolution(
            forwarding,
            ha_state,
            now_secs,
            looked_up_resolution,
            ingress_ifindex,
            ha_startup_grace_until_secs,
        );
        decision.resolution = redirect_session_via_fabric_if_needed(
            forwarding,
            enforced_resolution,
            fabric_link_ingress,
            resolved.metadata.ingress_zone,
        );
        // #9752: a terminal outcome arms this worker's purge walk (D8).
        if decision.resolution.disposition == ForwardingDisposition::TableUnavailable {
            flag_install_table_purge(worker_id);
        }
        let metadata = resolved.metadata.clone();
        let deferred_synced_promotion = (!keep_transient).then(|| DeferredSyncedPromotion {
            key: resolved_key.clone(),
            decision,
            metadata: metadata.clone(),
            origin: hit_origin,
            fabric_ingress,
            protocol,
            tcp_flags,
            now_ns,
        });
        let deferred_forwarding_revalidation =
            if forwarding_stale && !keep_transient {
                let policy_to_zone_id =
                    if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
                        metadata.egress_zone
                    } else {
                        forwarding.egress_zone_id(decision.resolution.egress_ifindex)
                    };
                let invalidate_policy_revalidation = previous_policy_to_zone_id
                    .is_some_and(|previous| previous != policy_to_zone_id);
                let owner_rg_id = matches!(
                    decision.resolution.disposition,
                    ForwardingDisposition::ForwardCandidate
                        | ForwardingDisposition::FabricRedirect
                        | ForwardingDisposition::HAInactive
                        | ForwardingDisposition::LocalDelivery
                )
                .then(|| owner_rg_for_resolution(forwarding, decision.resolution));
                Some(DeferredForwardingRevalidation {
                    resolution: decision.resolution,
                    owner_rg_id,
                    invalidate_policy_revalidation,
                })
            } else {
                None
            };
        return Some(ResolvedFlowSessionDecision {
            key: resolved_key.clone(),
            session_id,
            timeout_secs: 0,
            decision,
            source_nat_static,
            metadata,
            origin: hit_origin,
            source_nat_validation_key,
            created: false,
            install_failed: false,
            close_deferred: hit.close_deferred,
            deferred_forwarding_revalidation,
            deferred_synced_promotion,
            deferred_shared_materialization,
            deferred_synced_purge,
        });
    }
    // #11061: a synthetic/quarantined reply domain cannot be reinterpreted
    // through a mixed-zero NAT candidate. Let policy/native routing handle it;
    // building a reverse decision here could borrow a domain-0 MAIN session.
    if crate::session::is_quarantined_routing_domain(flow.forward_key.routing_domain) {
        return None;
    }
    // #7169: the main packet path — the one that INSTALLS a reverse session
    // from the match, making the adjudication durable. Revalidate the arrival
    // zone against the session being synthesized.
    //
    // A fabric-ingress packet is exempt and must be: it arrives on the fabric
    // link from the peer node, so its arrival zone is the fabric rather than
    // the flow's logical ingress. Constraining it would break cross-chassis
    // forwarding, which is a correctness break, not a hardening.
    let reverse_ingress = if fabric_ingress {
        crate::afxdp::shared_ops::ReverseIngress::Unconstrained
    } else {
        // #9383: key the zone ledger on the LOGICAL (VLAN unit) arrival ifindex,
        // not the raw physical one `meta.ingress_ifindex` carries.
        //
        // `ifindex_to_zone_id` deliberately PROPAGATES a zoned child unit's zone
        // onto its parent's ifindex (#921/#3618), so on a trunk whose units sit
        // in different zones the physical key answers with whichever unit won the
        // propagation. Measured on a `build_forwarding_state` trunk with unit 42
        // in `lan` and unit 43 UNZONED, both `parent_ifindex = 41`:
        // `ifindex_to_zone_id[41] = Some(lan)` while
        // `resolve_ingress_logical_ifindex(41, vlan 20) = Some(43)` and
        // `ifindex_to_zone_id[43] = None`. The physical lookup answers
        // `Zone(lan)` where the logical resolution answers "unzoned" — a
        // different ANSWER, not a different spelling of the same one.
        //
        // That matters here more than at most sites: a match admitted by a wrong
        // arrival zone makes `install_reverse_session_from_forward_match` MINT a
        // reverse session, and reverse entries are exempt from zone-policy
        // re-derivation by design (`policy_revalidation.rs` gate 1), so the
        // synthesized session then rides the established fast path with no
        // further adjudication. Every zone / filter / pre-routing-NAT admission
        // site already resolves the logical unit first (#3021/#5802).
        //
        // `.unwrap_or(ingress_ifindex)` is the same fallback those sites use: an
        // untagged port, and any arrival with no `(parent, vlan)` mapping,
        // resolves logical == physical and is byte-identical to pre-#9383.
        let arrival_logical = crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
            forwarding,
            ingress_ifindex,
            ingress_vlan_id,
        )
        .unwrap_or(ingress_ifindex);
        match forwarding.ifindex_to_zone_id.get(&arrival_logical).copied() {
            Some(z) => crate::afxdp::shared_ops::ReverseIngress::Zone(z),
            // Fail CLOSED. An unmapped arrival interface gives nothing to
            // revalidate against, and treating that as "no constraint" would
            // reopen the hole for exactly the traffic least accounted for.
            None => crate::afxdp::shared_ops::ReverseIngress::Unzoned,
        }
    };
    let forward_match = if let Some(prevalidated) = prevalidated_forward_nat_match {
        // Recheck the domain-zero reverse tuple at consumption time. The
        // caller's proof authorizes this candidate only, not a general
        // relaxation of reverse-NAT domain admission.
        let mut unique_reply_key = flow.forward_key.clone();
        unique_reply_key.routing_domain = 0;
        let Some(current_match) =
            sessions.find_unique_established_forward_nat_match_at(&unique_reply_key, now_ns)
        else {
            return None;
        };
        if current_match.key != prevalidated.key
            || !crate::afxdp::shared_ops::shared_forward_nat_candidate_is_unique(
                shared_nat_sessions,
                shared_owner_rg_indexes,
                &unique_reply_key,
                &current_match.key,
                current_match.decision.nat,
            )
        {
            return None;
        }
        current_match
    } else {
        lookup_forward_nat_across_scopes_at(
            sessions,
            shared_nat_sessions,
            forwarding,
            shared_owner_rg_indexes,
            &flow.forward_key,
            reverse_ingress,
            now_ns,
        )?
    };
    let (resolved, reverse_installed) = install_reverse_session_from_forward_match(
        sessions,
        session_map,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        peer_worker_commands,
        worker_commands_by_id,
        forwarding,
        ha_state,
        dynamic_neighbors,
        &flow.forward_key,
        forward_match,
        now_ns,
        now_secs,
        ha_startup_grace_until_secs,
        protocol,
        tcp_flags,
    );

    let mut decision = resolved.decision;
    let resolution_target = resolution_target_for_session(flow, decision);
    let looked_up_resolution =
        lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision)
            .resolution;
    let looked_up_resolution = super::prefer_local_forward_candidate_for_fabric_ingress(
        forwarding,
        ha_state,
        dynamic_neighbors,
        now_secs,
        fabric_ingress,
        resolution_target,
        install_table_name_for_session(forwarding, decision, resolution_target),
        looked_up_resolution,
    );
    let enforced_resolution = enforce_session_ha_resolution(
        forwarding,
        ha_state,
        now_secs,
        looked_up_resolution,
        ingress_ifindex,
        ha_startup_grace_until_secs,
    );
    decision.resolution = redirect_session_via_fabric_if_needed(
        forwarding,
        enforced_resolution,
        fabric_link_ingress,
        resolved.metadata.ingress_zone,
    );
    // #9752: terminal observation arms the purge walk (D8; reverse arm).
    if decision.resolution.disposition == ForwardingDisposition::TableUnavailable {
        flag_install_table_purge(worker_id);
    }
    let metadata = resolved.metadata;
    let install_info = sessions.installed_session_info(&flow.forward_key);
    Some(ResolvedFlowSessionDecision {
        key: flow.forward_key.clone(),
        session_id: install_info.map_or(0, |info| info.session_id),
        timeout_secs: install_info.map_or(0, |info| info.timeout_secs),
        decision,
        source_nat_static: None,
        metadata,
        origin: SessionOrigin::ReverseFlow,
        source_nat_validation_key: None,
        // #1861 §5.4 + AGY r1 F1: `created` reports the ACTUAL install
        // outcome (was unconditionally true — session_creates over-counted
        // at cap and publish_bpf_conntrack_entry fired for a session that
        // does not exist locally). `install_failed` keeps the failed-repair
        // reply out of the flow cache so the repair re-fires per packet
        // and succeeds on the first packet after the table drops below
        // max_sessions.
        created: reverse_installed,
        install_failed: !reverse_installed,
        // #10636: reverse-synthesized from a forward match (close, if any,
        // was stamped at install); never a deferred local hit.
        close_deferred: false,
        deferred_synced_promotion: None,
        deferred_shared_materialization: None,
        deferred_forwarding_revalidation: None,
        deferred_synced_purge: None,
    })
}

pub(super) fn redirect_session_via_fabric_if_needed(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
    fabric_ingress: bool,
    ingress_zone: u16,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive {
        return resolution;
    }
    if fabric_ingress {
        return resolution;
    }
    resolve_fabric_redirect_for_ingress_zone(forwarding, Some(ingress_zone))
        .unwrap_or(resolution)
}

pub(super) fn enforce_session_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
    ha_startup_grace_until_secs: u64,
) -> ForwardingResolution {
    let enforced = enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolution);
    if enforced.disposition == ForwardingDisposition::HAInactive
        && should_bypass_unseeded_tunnel_ha(
            forwarding,
            ha_state,
            now_secs,
            resolution,
            ingress_ifindex,
            ha_startup_grace_until_secs,
        )
    {
        return resolution;
    }
    enforced
}


#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "deleted_first_policy_purge_9526_tests.rs"]
mod deleted_first_policy_purge_9526_tests;
#[cfg(test)]
#[path = "pbr_install_table_9752_tests.rs"]
mod pbr_install_table_9752_tests;
// #4800: publish + sibling-replication contention accounting for the
// new-flow-install ceiling harness. Kept in its own file rather than
// appended to `tests.rs` (already ~7k lines).
#[cfg(test)]
#[path = "newflow_contention_tests.rs"]
mod newflow_contention_tests;
// #9951: established-session routing revocation regression and controls.
#[cfg(test)]
#[path = "leak_revoke_9951_tests.rs"]
mod leak_revoke_9951_tests;
// #9517: the worker publish path's routing-domain WIRING, driven against the
// `bpf_map` write recorder. Its own file for the same reason as the one above.
#[cfg(test)]
#[path = "routing_domain_publish_9517_tests.rs"]
mod routing_domain_publish_9517_tests;
// #9560: the steering map's shared-row DELETE, driven against the same recorder.
#[cfg(test)]
#[path = "steering_row_owners_9560_tests.rs"]
mod steering_row_owners_9560_tests;

// #6600: the coordinator's pre-publish NAT reservation resolves the synced zone
// pair through the SAME helper the worker-side upsert uses, so the two cannot
// land on different allocators.
pub(in crate::afxdp) use commands::upsert_synced::synced_source_nat_zone_pair;

/// #7919: one worker's answer to a `QuerySessionCounters` request.
///
/// `found` is carried separately from the counters because "I hold this session
/// and it has no traffic" and "I do not hold this session" are different facts,
/// and the query exists to tell them apart. A single zeroed row would collapse
/// them and answer neither.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionCounterAnswer {
    pub sequence: u64,
    pub found: bool,
    /// True when the held entry is a peer-synced/replica origin. A replica
    /// reporting VOLUME would falsify the premise the investigation rests on —
    /// that replicas are created at zero and cannot advance — so the answer
    /// carries what it would take to notice that.
    pub replica: bool,
    pub fwd_packets: u64,
    pub fwd_bytes: u64,
    pub rev_packets: u64,
    pub rev_bytes: u64,
}
