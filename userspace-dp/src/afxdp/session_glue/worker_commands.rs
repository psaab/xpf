use super::*;

pub(in crate::afxdp) struct WorkerCommandResults {
    pub cancelled_keys: Vec<SessionKey>,
    /// #6457: every session key dropped by a `WorkerCommand::DeleteSynced`
    /// this tick, recorded unconditionally by `handle_delete_synced` (even
    /// when the worker's session table had no entry — a stale flow-cache
    /// slot outlives its table entry, so the invalidate must not gate on
    /// the lookup). `apply_worker_commands` has no `BindingWorker` access;
    /// the worker loop (`worker/loop_body/mod.rs`) drains this list and
    /// calls `flow_cache.invalidate_slot(&key, binding.ifindex)` on every
    /// binding it owns — the same pattern #3776's `reap_expired_sessions`
    /// uses on the GC path — so a revoked 5-tuple MISSES the cache on its
    /// next packet and re-runs full session lookup + policy instead of
    /// forwarding via a stale cached permit with no live session (the
    /// operator `clear security flow session`, cluster-stale sweep, and HA
    /// DeleteSynced paths all funnel through this command).
    pub deleted_synced_keys: Vec<SessionKey>,
    /// #10612: every session key refused by the stale-replay fence this tick
    /// (an `UpsertSynced` whose recorded zones are absent from the current
    /// validated set — see `synced_entry_is_stale_replay`). `apply_worker_commands`
    /// has no shared-map access; the worker loop drains this list and evicts
    /// each key from shared authority, so the purge-deleted row stays deleted
    /// on both sides. Same record-here/apply-where-the-handles-are split as
    /// `deleted_synced_keys` above.
    pub stale_replay_dropped_keys: Vec<SessionKey>,
    /// #11360: position-ready imported keys repaired from shared authority.
    /// The worker loop applies them before later queued commands.
    pub session_import_repairs: Vec<worker_queue::SessionImportRepair>,
    pub exported_sequences: Vec<u64>,
    /// #2653: the union of owner RGs requested by every
    /// `ExportOwnerRGSessions` command processed this tick. The command
    /// handler NO LONGER emits the open deltas itself — doing so pushed the
    /// entire owned-session set (up to `DEFAULT_MAX_SESSIONS` = 32x the 4096
    /// delta ring) into the ring in one shot, overflowing it and silently
    /// dropping sessions 4097..N from the HA bulk snapshot. Instead the
    /// handler records the RGs here and the worker loop performs the same
    /// chunked drain-as-you-export the #2442 loss-of-sync resync uses
    /// (collect candidates -> emit in < cap chunks -> drain between chunks),
    /// so the complete snapshot ships without overflowing the ring.
    pub export_owner_rgs: Vec<i32>,
    /// #9856: kick epoch for this tick's export, captured at the FIRST
    /// Export-command accept (`SessionTable::current_epoch`). None when no
    /// Export command was accepted. NOTE (rebase duty): Eng9720's
    /// `transition_debt_pending` lands LAST post-#10141-merge; this field
    /// moves after it with the two guard strings updated in the same commit.
    pub export_kick_epoch: Option<u64>,
    pub shaped_tx_requests: Vec<TxRequest>,
    /// #941 Work item C: set when at least one
    /// `WorkerCommand::VacateAllSharedExactSlots` was processed.
    /// `apply_worker_commands` cannot vacate directly because it has
    /// no `BindingWorker` access — the outer poll loop in `worker.rs`
    /// dispatches based on this flag.
    pub vacate_all_shared_exact_slots: bool,
    /// #7201: the shared queue still held commands after this call's
    /// [`WORKER_COMMAND_DRAIN_BUDGET`] slice was taken.
    ///
    /// The worker loop MUST fold this into `did_work`. It is not a statistic:
    /// `did_work` is set only by `poll_binding`, so without this the loop
    /// classifies a budget-split drain as IDLE, and on a node with no traffic
    /// yet — the standby that has just been promoted, which is exactly when the
    /// RG-activation burst arrives — `idle_iters` passes `IDLE_SPIN_ITERS` and
    /// every remaining slice waits behind a 1 ms `poll(2)` in Interrupt mode.
    /// The budget would then have replaced a bounded 3.85 ms stall with ~16 ms
    /// of drain.
    pub commands_backlogged: bool,
    /// #9720: transition-debt ops remain for a future pass.
    ///
    /// True when debt was skipped (queue lock contended — position unknown)
    /// or is still counting down (backlog remains ahead of it). The worker
    /// loop carries this across passes and applies while set, which is what
    /// closes the contended-with-empty stranding window (the tunnel
    /// drain-wait polls queues read-only, so that window is real). It is NOT
    /// folded into `did_work`: unlike a backlog, pending debt needs no
    /// immediate revisit for ring health — the next pass is one poll away.
    pub transition_debt_pending: bool,
    /// #11360: imported-session repair debt remains latched for a future pass.
    pub session_import_repair_pending: bool,
}

impl WorkerCommandResults {
    /// The no-work result: nothing dispatched, nothing left behind.
    ///
    /// `commands_backlogged: false` is load-bearing, not a filler default — it
    /// is what keeps an empty or lock-contended pass out of `did_work`.
    pub(in crate::afxdp) fn empty() -> Self {
        WorkerCommandResults {
            cancelled_keys: Vec::new(),
            deleted_synced_keys: Vec::new(),
            stale_replay_dropped_keys: Vec::new(),
            session_import_repairs: Vec::new(),
            exported_sequences: Vec::new(),
            export_owner_rgs: Vec::new(),
            export_kick_epoch: None,
            shaped_tx_requests: Vec::new(),
            vacate_all_shared_exact_slots: false,
            commands_backlogged: false,
            transition_debt_pending: false,
            session_import_repair_pending: false,
        }
    }
}

pub(super) fn force_live_redirect_for_worker_synced_entry(key: &SessionKey,
decision: SessionDecision,
metadata: &SessionMetadata,
origin: SessionOrigin,
allow_replace_local: bool,
has_routing_domains: bool,) -> bool { allow_replace_local
    && uses_kernel_local_session_map_entry(key, decision, metadata, origin, has_routing_domains) }

pub(in crate::afxdp) fn apply_worker_commands(commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
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
scratch: &mut VecDeque<WorkerCommand>,) -> WorkerCommandResults {
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
            WorkerCommand::QuerySessionCounters {
                sequence,
                key,
                reply,
            } => {
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
                *reply.lock().unwrap_or_else(|e| e.into_inner()) = Some(answer);
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
                worker_id,
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
    worker_id: u32,
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
            if !surviving.is_empty()
                && commands::handle_demote_owner_rgs(
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
                )
            {
                flag_install_table_purge(worker_id);
            }
        }
        TransitionDebtKind::Refresh => {
            let surviving: Vec<i32> = op.rgs().iter().copied().filter(rg_is_active).collect();
            worker_queue::HA_TRANSITION_REFRESH_STALE_SKIPPED
                .fetch_add((op.rgs().len() - surviving.len()) as u64, Ordering::Relaxed);
            if !surviving.is_empty()
                && commands::handle_refresh_owner_rgs(
                    sessions,
                    session_map,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    surviving,
                    now_ns,
                    now_secs,
                )
            {
                flag_install_table_purge(worker_id);
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

pub(in crate::afxdp) fn replicate_session_upsert(worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
worker_command_queues: &WorkerCommandQueues,
entry: &SyncedSessionEntry,) {
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
pub(in crate::afxdp) struct DeleteReplicationOutcome {
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
pub(super) fn worker_id_for_command_queue(worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
queue: &Arc<Mutex<VecDeque<WorkerCommand>>>,) -> Option<u32> { worker_commands_by_id
    .iter()
    .find(|(_, candidate)| Arc::ptr_eq(candidate, queue))
    .map(|(id, _)| *id) }

pub(in crate::afxdp) fn replicate_session_delete(worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
key: &SessionKey,) {
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
pub(in crate::afxdp) fn replicate_purge_delete(worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
key: &SessionKey,
domain: u32,
check: u32,) {
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
pub(in crate::afxdp) fn replicate_session_delete_repairing(peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
forwarding: &ForwardingState,
key: &SessionKey,
nat: NatDecision,
is_reverse: bool,
now_ns: u64,) -> DeleteReplicationOutcome {
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
pub(in crate::afxdp) fn replicate_session_delete_conditional(peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
worker_commands_by_id: &BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
forwarding: &ForwardingState,
key: &SessionKey,
nat: NatDecision,
is_reverse: bool,
now_ns: u64,
expected_id: u64,
companion: Option<SessionKey>,) -> DeleteReplicationOutcome {
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

