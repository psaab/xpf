//! #1328 Phase 2 — worker bringup phase.
//!
//! #6240: the bring-up transaction is decomposed into cohesive phase
//! helpers, all kept in THIS module (no one-file-per-phase). `bring_up_workers`
//! is now a short shell that sequences them and — critically — keeps the
//! two-armed #4952 rollback DECISION visible and distinct in the shell
//! (spawn-fail returns WITHOUT `stop_inner`; bind-incomplete calls
//! `stop_inner(false)`); no helper ever calls `stop_inner`. The phase order is
//! preserved verbatim: clamp the ring depth ([`clamp_ring_entries`]),
//! [`plan_workers`] (build per-worker `BindingPlan` lists + live/identities +
//! sizing + the `Planned` stage), [`publish_runtime`] (move the BPF map FDs onto
//! `coord.bpf_maps` + publish the mirror-target/CoS owner maps),
//! [`replay_preserved_sessions`] (build the command queues + replay preserved
//! synced sessions), [`ensure_resolver`] (best-effort on-demand neighbor
//! resolver, ATTEMPTED before worker launch), [`spawn_workers`] (the per-worker
//! spawn loop with the #925 panic slot + the #6242 post-spawn-success record
//! insert → a typed [`LaunchOutcome`]), [`await_readiness`] (the #5143
//! startup-readiness barrier), then [`start_post_readiness_neighbor_services`]
//! (neighbor monitor + warmer + the local tunnel/WG reconcile). Final
//! `refresh_bindings` is invoked by the orchestrator, not here.
use super::ReconcileSnapshotFds;
// Pull everything the bringup body needs from afxdp scope via the
// coordinator's own re-imports. coordinator/mod.rs starts with
// `use super::*;` which makes all afxdp items visible there; doing
// the same here brings them into bringup's scope.
use super::super::super::*;
use super::super::supervisor::{spawn_supervised_aux, spawn_supervised_worker};
use super::super::{Coordinator, WorkerHandle, WorkerRuntimeRecord};

/// #5143: how long `bring_up_workers` waits for every newly-started worker to
/// report its startup readiness (the set of planned bindings whose XSK
/// actually bound) before it fails the reconcile closed. A worker that never
/// reports within this bound is treated as failed — the barrier does NOT block
/// forever. 10s mirrors the HA sync-hold ceiling: comfortably above a healthy
/// worker's setup cost (per-worker TSC calibration ~10ms + UMEM mmap + XSK
/// bind, well under a second even for a full 6-queue VF) yet bounded so a hung
/// worker cannot wedge the control socket indefinitely. The COMMON failure — a
/// worker that finished setup with a PARTIAL binding set — reports immediately,
/// so the barrier fails fast without approaching this deadline; only a worker
/// that dies/hangs inside setup consumes the full budget.
const WORKER_STARTUP_BARRIER_TIMEOUT_NS: u64 = 10_000_000_000;

/// #5143: the two DISTINCT post-teardown worker-bringup failures, both raised
/// AFTER `tear_down` has stopped the old workers (so the data plane HAS moved
/// and there is no prior-state restore — only fail-closed bookkeeping + a
/// retry/last-good reconcile). `reconcile` maps each to its own
/// [`ReconcileError`] variant so the control handler can fail closed and NOT
/// persist the broken snapshot as the boot baseline.
pub(super) enum WorkerBringUpError {
    /// #4952: a worker thread failed to SPAWN (`spawn_supervised_worker` ->
    /// `pthread_create` EAGAIN/ENOMEM). #6244: carries the preserved typed
    /// [`ReconcileStage::SpawnWorkerFailed`] identity (was a stage `String`).
    Spawn(ReconcileStage),
    /// #5143: a worker SPAWNED successfully but its in-thread XSK/UMEM bind
    /// did not bring up its FULL planned binding set (a partial/empty bind), or
    /// it never reported readiness within the bounded deadline. HEARTBEAT !=
    /// READINESS — a live heartbeat over an incomplete binding set is the
    /// silent forwarding outage this guards. #6244: carries the preserved typed
    /// [`ReconcileStage::WorkerBindIncomplete`] identity (was a stage `String`).
    BindIncomplete(ReconcileStage),
}

/// #6240: the outcome of the per-worker spawn loop ([`spawn_workers`]),
/// returned to the [`bring_up_workers`] shell so the two-armed #4952 rollback
/// DECISION stays in the shell — `spawn_workers` itself NEVER calls
/// `stop_inner`.
enum LaunchOutcome {
    /// #4952 ARM 1: a worker thread failed to SPAWN. Carries the preserved typed
    /// [`ReconcileStage::SpawnWorkerFailed`] identity (already recorded on
    /// `coord.last_reconcile_stage` by the loop). The launched workers `0..N-1`
    /// KEEP their records — a failed worker never registered one (post-spawn
    /// insert) — so the shell returns `Err(Spawn)` WITHOUT `stop_inner`.
    SpawnFailed(ReconcileStage),
    /// Every planned worker spawned. Carries the set of spawned worker ids and
    /// the per-worker DISPATCHED planned-slot sets the #5143 readiness barrier
    /// checks `bound == planned` against.
    AllSpawned {
        spawned_worker_ids: Vec<u32>,
        planned_slots_by_worker: BTreeMap<u32, std::collections::BTreeSet<u32>>,
    },
}

/// Bring up the worker threads for the just-applied snapshot.
///
/// #4952: this runs on the POST-TEARDOWN destructive path — `tear_down`
/// has already stopped the previous workers, so a worker-thread spawn
/// failure here leaves the affected queue set with NO XSK-bound worker
/// (a silent forwarding outage). The spawn (`spawn_supervised_worker` ->
/// `thread::Builder::spawn` -> `pthread_create`) can return EAGAIN/ENOMEM
/// under resource exhaustion. On the FIRST such failure this ABORTS the
/// remaining launches (the data plane is already broken — spawning more
/// XSK-bound workers cannot restore forwarding and only compounds the
/// pressure), PRESERVES the `spawn_worker_failed:<id>:<err>` stage (it does
/// NOT overwrite it with `spawned:..`), skips the auxiliary-thread bring-up,
/// and returns `Err(WorkerBringUpError::Spawn(stage))`. The caller
/// (`reconcile`) maps that to `ReconcileError::WorkerSpawn` so the control
/// handler fails closed and does NOT persist the broken snapshot as the boot
/// baseline. On success returns `Ok(())`.
///
/// #5143: a SPAWN success only proves the thread exists — NOT that its
/// in-thread XSK/UMEM binds brought up the full planned queue set. A worker
/// that bound a PARTIAL/EMPTY set still HEARTBEATS, so the thread-death
/// supervisor is satisfied and (pre-#5143) this returned `Ok`, committing a
/// silent forwarding outage. #4952's spawn-error propagation does not catch it
/// (the spawn succeeded). So after the spawn loop this runs a STARTUP READINESS
/// BARRIER: every spawned worker reports the slot set it actually bound (a
/// `WorkerStartupReport` over a per-reconcile `mpsc` channel, sent from
/// `worker_loop` after setup), and the barrier waits — under a bounded deadline
/// ([`WORKER_STARTUP_BARRIER_TIMEOUT_NS`]; a worker that never reports in time
/// is treated as failed, NOT blocked forever) — for `bound == planned` per
/// worker. On ANY shortfall/timeout it FAILS CLOSED: `stop_inner(false)` stops +
/// joins the newly-started workers (no leaked live-but-unbound worker), preserves
/// the `worker_bind_incomplete:..` stage, and returns
/// `Err(WorkerBringUpError::BindIncomplete(stage))`, which `reconcile` maps to
/// `ReconcileError::WorkerBindIncomplete` (handled the same fail-closed way as
/// `WorkerSpawn`). HEARTBEAT != READINESS: the reconcile transaction now
/// requires one READY binding per required plan.
///
/// Full pre-teardown preflight of the spawn is not tractable — a real
/// `pthread_create` cannot be probed without spawning the thread, and the
/// old workers must be torn down first to free the XSK queue bindings the
/// new workers claim. So this is the minimal fail-closed guarantee (do not
/// persist a known-broken snapshot); a staged spawn-before-teardown is a
/// possible follow-up.
///
/// #6240: the body is a short shell over the phase helpers below. The phase
/// ORDER is load-bearing and preserved exactly: FD ownership transfer BEFORE any
/// launch; mirror/CoS publication BEFORE replay/launch; preserved sessions +
/// command queues BEFORE launch; the resolver ATTEMPT BEFORE worker launch; ALL
/// launches BEFORE the readiness barrier. The two-armed rollback decision stays
/// HERE, in the shell (never in a helper).
pub(super) fn bring_up_workers(
    coord: &mut Coordinator,
    snapshot: &ConfigSnapshot,
    bindings: &mut [BindingStatus],
    fds: ReconcileSnapshotFds,
    ring_entries: usize,
    tunnel_purge_ids: &[u16],
) -> Result<(), WorkerBringUpError> {
    let ring_entries = clamp_ring_entries(ring_entries);
    // Phase: PLAN. Build the per-worker binding plans (+ live/identities +
    // sizing + the `Planned` stage) from the snapshot and the just-opened map
    // FDs, read by RAW descriptor — the `OwnedFd`s are still owned by `fds`.
    let workers = plan_workers(coord, snapshot, bindings, &fds, ring_entries);
    // Capture the values the later phases need BEFORE `fds` is moved into
    // `publish_runtime`: the session map's raw descriptor (replay) and the DNAT
    // table fds (Copy; the worker launch bundle). The replay writes as the
    // coordinator, which claims no steering row (#9560), through the coordinator's
    // one registry.
    let session_map_raw_fd = fds.session_map_fd.fd;
    let session_map_owners = Arc::clone(&coord.steering_owners);
    let dnat_fds = fds.dnat_fds;
    // Phase: PUBLISH. Move the OwnedFds onto `coord.bpf_maps` and publish the
    // mirror-target + CoS owner/active-shard maps the workers read — BEFORE any
    // replay or launch.
    publish_runtime(coord, &workers, fds);
    // Phase: REPLAY. Build the per-worker command queues and replay preserved
    // synced sessions into the session map — BEFORE launch.
    let worker_command_queues = replay_preserved_sessions(
        coord,
        &workers,
        tunnel_purge_ids,
        SteeringMap {
            fd: session_map_raw_fd,
            owners: &session_map_owners,
            holder: crate::afxdp::bpf_map::SteeringHolder::Coordinator,
        },
    );
    // Phase: RESOLVER (best-effort, ATTEMPTED before worker launch so every
    // worker's `WorkerSharedDataplane::from_coord` clones a live handle). A
    // spawn failure leaves it `None` and workers still launch (with
    // `resolver: None`) — the invariant is attempt-before-launch, NOT
    // resolver-must-exist, so the resolver is NEVER threaded into
    // `spawn_workers`.
    let _ = ensure_resolver(coord);
    // Phase: SPAWN. The startup-report channel is created HERE, in the shell,
    // and the SENDER is passed BY REFERENCE into the spawn loop (each worker
    // clones it). Keeping the original sender alive in the shell through the
    // readiness barrier preserves the exact channel-disconnect semantics
    // `await_readiness` relies on (the barrier never sees `Disconnected` while
    // this sender lives).
    let (startup_report_tx, startup_report_rx) = mpsc::channel::<WorkerStartupReport>();
    match spawn_workers(
        coord,
        workers,
        // #6311: the node discriminator for every spawned worker's session-id
        // namespace. Read from the SNAPSHOT being brought up, so a node id that
        // changed since the last reconcile takes effect with the plan that
        // carried it.
        snapshot.node_id,
        worker_command_queues,
        dnat_fds,
        &startup_report_tx,
    ) {
        // #4952 differential ARM 1 (stays in the shell): a spawn failed on the
        // post-teardown path. Return WITHOUT `stop_inner` — the already-launched
        // workers KEEP their records (reclaimed by the next reconcile's
        // teardown); the failed worker never registered one.
        LaunchOutcome::SpawnFailed(stage) => {
            eprintln!(
                "xpf-userspace-dp: worker bring-up FAILED ({stage}); a queue set has no \
                 XSK-bound worker after teardown — failing reconcile closed"
            );
            return Err(WorkerBringUpError::Spawn(stage));
        }
        LaunchOutcome::AllSpawned {
            spawned_worker_ids,
            planned_slots_by_worker,
        } => {
            // #5143 STARTUP READINESS BARRIER. Every worker SPAWNED, but a spawn
            // only proves the thread exists — NOT that its in-thread XSK/UMEM
            // binds brought up the full planned queue set. Wait (under a bounded
            // deadline) for each spawned worker to report the slot set it
            // actually bound, then require bound == planned. A worker that bound
            // a PARTIAL/EMPTY set (the #5143 silent forwarding outage) or never
            // reported in time fails the reconcile CLOSED.
            if let Some(stage) = await_readiness(
                &startup_report_rx,
                &spawned_worker_ids,
                &planned_slots_by_worker,
            ) {
                eprintln!(
                    "xpf-userspace-dp: worker bring-up FAILED ({stage}); a spawned worker did not \
                     bind its full planned queue set after teardown — failing reconcile closed"
                );
                // #4952 differential ARM 2 (stays in the shell): stop + JOIN the
                // newly-started workers (the teardown path) so no live-but-unbound
                // worker keeps heartbeating past this fail-closed reconcile, and
                // clear the coordinator worker state so a retry / last-good
                // reconcile starts from a coherent baseline. Preserved synced
                // sessions are kept (`clear_synced_state=false`). #6244:
                // `stop_inner` no longer writes `last_reconcile_stage`, so the
                // typed bind-incomplete identity is recorded once, after the
                // teardown, and survives.
                coord.stop_inner(false);
                // #8558: `stop_inner` above emptied `workers.live`, which is
                // what makes `refresh_bindings` route every slot through
                // `zero_unbound_slot` and erase the per-slot `last_error` the
                // bind actually produced. Re-record the causes on the
                // coordinator, AFTER the teardown that clears the map, so the
                // status the Go manager polls carries them for as long as the
                // fault lasts. Ordering is the whole fix: recorded before
                // `stop_inner` they would be cleared again.
                record_bind_failure_causes(coord, &stage);
                coord.last_reconcile_stage = stage.clone();
                return Err(WorkerBringUpError::BindIncomplete(stage));
            }
        }
    }
    coord.last_reconcile_stage = ReconcileStage::Spawned {
        // #6242: the `Spawned` stage's `handles` field is the worker COUNT,
        // now sourced from the consolidated `records` map (was `handles`).
        handles: coord.workers.records().len(),
        identities: coord.workers.identities.len(),
        live: coord.workers.live.len(),
    };
    // Phase: POST-READINESS neighbor services + the local tunnel/WG reconcile.
    start_post_readiness_neighbor_services(coord);
    Ok(())
}

/// #2524: clamp the configured ring depth to the shared sanity ceiling
/// ([`MAX_RING_ENTRIES`]) with a floor of 64 — the helper-side backstop for the
/// Go commit-time bound. The Go gate rejects any normally-committed value >
/// MAX_RING_ENTRIES, so a clamp here only fires on a config persisted by an
/// older binary (before the bound landed). Warn so an operator on the
/// stale-binary path can see the configured ring depth was capped rather than
/// silently running a smaller ring than configured.
fn clamp_ring_entries(ring_entries: usize) -> u32 {
    if ring_entries > MAX_RING_ENTRIES as usize {
        eprintln!(
            "xpf-dp: ring-entries {ring_entries} exceeds MAX_RING_ENTRIES {}; \
             capping (config predates the #2524 commit-time bound)",
            MAX_RING_ENTRIES
        );
    }
    ring_entries.max(64).min(MAX_RING_ENTRIES as usize) as u32
}

/// #6240 phase: PLAN. Build the per-worker `BindingPlan` lists from the
/// registered bindings and the just-opened BPF map FDs (read by RAW descriptor
/// — the `OwnedFd`s stay owned by `fds`, which `publish_runtime` moves onto
/// `coord.bpf_maps` next), insert the per-slot live-state + identity, apply the
/// shared-UMEM policy, project the resulting shared-UMEM status back onto
/// `bindings`, record the sizing values, and set the `Planned` stage. Returns
/// the worker->plans map the rest of the transaction consumes. Verbatim move of
/// the pre-#6240 inline block.
fn plan_workers(
    coord: &mut Coordinator,
    snapshot: &ConfigSnapshot,
    bindings: &mut [BindingStatus],
    fds: &ReconcileSnapshotFds,
    ring_entries: u32,
) -> BTreeMap<u32, Vec<BindingPlan>> {
    let ReconcileSnapshotFds {
        map_fd,
        heartbeat_map_fd,
        session_map_fd,
        conntrack_v4_fd,
        conntrack_v6_fd,
        ..
    } = fds;
    let mut workers: BTreeMap<u32, Vec<BindingPlan>> = BTreeMap::new();
    for binding in bindings.iter_mut() {
        if !binding.registered || binding.ifindex <= 0 {
            binding.ready = false;
            continue;
        }
        let live = Arc::new(BindingLiveState::new());
        coord.workers.live.insert(binding.slot, live.clone());
        let identity = BindingIdentity {
            slot: binding.slot,
            queue_id: binding.queue_id,
            worker_id: binding.worker_id,
            interface: Arc::<str>::from(binding.interface.as_str()),
            ifindex: binding.ifindex,
        };
        coord.workers.identities.insert(binding.slot, identity);
        workers
            .entry(binding.worker_id)
            .or_default()
            .push(BindingPlan {
                status: binding.clone(),
                live,
                xsk_map_fd: map_fd.fd,
                heartbeat_map_fd: heartbeat_map_fd.fd,
                session_map: crate::afxdp::bpf_map::SteeringMapRef::new(
                    session_map_fd.fd,
                    Arc::clone(&coord.steering_owners),
                    crate::afxdp::bpf_map::SteeringHolder::Worker(binding.worker_id),
                ),
                conntrack_v4_fd: conntrack_v4_fd.as_ref().map(|f| f.fd).unwrap_or(-1),
                conntrack_v6_fd: conntrack_v6_fd.as_ref().map(|f| f.fd).unwrap_or(-1),
                ring_entries,
                bind_strategy: preferred_bind_strategy(binding),
                poll_mode: coord.poll_mode,
                shared_umem: SharedUmemBindingPlan::private(),
            });
    }
    for plans in workers.values_mut() {
        plans.sort_by_key(|plan| (plan.status.queue_id, plan.status.ifindex, plan.status.slot));
    }
    apply_shared_umem_policy_to_workers(snapshot, &mut workers);
    let shared_umem_status_by_slot = workers
        .values()
        .flat_map(|plans| plans.iter())
        .map(|plan| {
            (
                plan.status.slot,
                (
                    plan.status.shared_umem_mode.clone(),
                    plan.status.shared_umem_group.clone(),
                    plan.status.shared_umem_socket_role.clone(),
                    plan.status.shared_umem_disabled_reason.clone(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for binding in bindings.iter_mut() {
        if let Some((mode, group, role, reason)) = shared_umem_status_by_slot.get(&binding.slot) {
            binding.shared_umem_mode.clone_from(mode);
            binding.shared_umem_group.clone_from(group);
            binding.shared_umem_socket_role.clone_from(role);
            binding.shared_umem_disabled_reason.clone_from(reason);
        }
    }
    let planned_bindings: usize = workers.values().map(|group| group.len()).sum();
    coord.workers.last_planned_workers = workers.len();
    coord.workers.last_planned_bindings = planned_bindings;
    // #1830 follow-up (Codex review on PR #1841): record the SIZING
    // value for per-worker-id-indexed structures separately from the
    // count. Worker ids can be sparse here — the binding loop above
    // skips unregistered/invalid bindings, so a surviving high-id
    // worker can outlive every lower id (reachable via the runtime
    // binding/queue unregister handlers). Sizing the v8 lease arrays /
    // rotation scratch / V_min floors from workers.len() would put
    // that worker out of range (acquire_v8 returns 0 + debug-panics).
    coord.workers.last_planned_worker_slots = planned_worker_slots(&workers);
    coord.last_reconcile_stage = ReconcileStage::Planned {
        workers: coord.workers.last_planned_workers(),
        bindings: coord.workers.last_planned_bindings(),
        live: coord.workers.live.len(),
    };
    eprintln!(
        "xpf-userspace-dp: reconcile planned_workers={} planned_bindings={} live_slots={}",
        workers.len(),
        planned_bindings,
        coord.workers.live.len()
    );
    workers
}

/// #6240 phase: PUBLISH. Move the owned BPF map FDs onto `coord.bpf_maps`
/// (transferring ownership so `stop_inner`'s teardown order governs their drop —
/// join workers, delete XSK/heartbeat slots while the FDs live, THEN drop the
/// `OwnedFd`s) and publish the mirror-target + CoS owner/active-shard maps the
/// workers read — BEFORE any replay or launch. Verbatim move of the pre-#6240
/// inline block (the `session_map_raw_fd` read stays in the shell, before the
/// move).
fn publish_runtime(
    coord: &mut Coordinator,
    workers: &BTreeMap<u32, Vec<BindingPlan>>,
    fds: ReconcileSnapshotFds,
) {
    let ReconcileSnapshotFds {
        map_fd,
        heartbeat_map_fd,
        session_map_fd,
        conntrack_v4_fd,
        conntrack_v6_fd,
        dnat_table_fd,
        dnat_table_v6_fd,
        dnat_fds: _,
        forwarding: _,
    } = fds;
    // #7209: ONE store of the whole set, so a reader can never observe a
    // half-populated generation (e.g. a live `session_map_fd` beside a stale
    // `dnat_table_fd`). The previous set's descriptors are closed when the last
    // holder releases its `Arc`.
    coord
        .bpf_maps
        .store(Arc::new(crate::afxdp::coordinator::BpfMaps {
            map_fd: Some(map_fd),
            heartbeat_map_fd: Some(heartbeat_map_fd),
            session_map_fd: Some(session_map_fd),
            conntrack_v4_fd,
            conntrack_v6_fd,
            dnat_table_fd,
            dnat_table_v6_fd,
        }));
    let worker_binding_ifindexes = workers
        .iter()
        .map(|(worker_id, binding_plans)| {
            (
                *worker_id,
                binding_plans
                    .iter()
                    .map(|plan| plan.status.ifindex)
                    .collect::<std::collections::BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let owner_map = super::super::build_cos_owner_worker_by_queue(&coord.forwarding, workers);
    coord
        .mirror_targets
        .store(Arc::new(super::super::build_mirror_target_map(
            &coord.workers.identities,
            &coord.workers.live,
        )));
    let active_shards_by_egress_ifindex =
        super::super::build_cos_active_shards_by_egress_ifindex_with_fallback_ifindexes(
            &coord.forwarding,
            &worker_binding_ifindexes,
            &worker_binding_ifindexes,
        );
    coord.refresh_cos_runtime_maps(owner_map, active_shards_by_egress_ifindex);
}

/// #6240 phase: REPLAY. Build the per-worker command queues and replay the
/// preserved synced sessions into the session map (seeding the session table +
/// the queues) BEFORE launch, recording the `ReplayedSynced` stage when any
/// replayed. Returns the shared command-queue map the spawn loop hands to each
/// worker. Verbatim move of the pre-#6240 inline block.
/// #8157: the replay set is derived from the LIVE shared synced map HERE,
/// rather than from a `Vec` cloned before `tear_down`.
///
/// The old shape had a window. `teardown::tear_down` cloned
/// `snapshot_shared_session_entries()` before `stop_inner(false)`, and the
/// replay published that clone — so an entry landing in the shared map between
/// the clone and this point was absent from the replay, never published to the
/// new session map (the fd is `None` for the whole reconcile), and never
/// replayed, while `upsert_synced_session` still answered Go `Applied`. A split
/// truth with no signal.
///
/// Reading the map here closes it by construction: the read happens after every
/// arrival the reconcile could race. This is sound because `stop_inner(false)`
/// does NOT clear `sessions.synced` — the clear is gated on
/// `clear_synced_state`, which only full shutdown passes (see #6652).
///
/// The tunnel-remap filter MOVED here with the set it applies to.
/// `apply_snapshot` computes `tunnel_purge_ids` and has already purged those
/// sessions from the live map, so for every entry that predates the purge the
/// filter is redundant — it is kept for the one case it still covers, an entry
/// for a purged tunnel arriving AFTER the purge. It calls the same
/// `filter_replayed_synced_sessions` predicate the snapshot phase used, not a
/// paraphrase, so the two cannot disagree about what a purged tunnel is.
///
/// REACHABLE AS OF #7209. This was written as a prerequisite, with the note
/// that the snapshot-wide `ServerState` mutex excluded `sync_session` for the
/// whole reconcile so nothing could arrive in the window it closes — landing it
/// afterwards would have meant shipping the race first. #7209 has since taken
/// `sync_session` off that mutex, so an import CAN now land mid-reconcile and
/// this read is what includes it. The ordering held: the guard was in place
/// before the race it guards became possible.
/// Visibility is `pub(in crate::afxdp)` for the #8157 test in `ha_tests.rs`,
/// which reuses that module's synced-session fixtures rather than duplicating
/// them here — a duplicated fixture is a fixture that drifts.
pub(in crate::afxdp) fn replay_preserved_sessions(
    coord: &mut Coordinator,
    workers: &BTreeMap<u32, Vec<BindingPlan>>,
    tunnel_purge_ids: &[u16],
    session_map: SteeringMap<'_>,
) -> Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>> {
    let worker_command_queues: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>> = Arc::new(
        workers
            .keys()
            .copied()
            .map(|worker_id| (worker_id, Arc::new(Mutex::new(VecDeque::new()))))
            .collect(),
    );
    let mut replay_entries = coord.snapshot_shared_session_entries();
    crate::afxdp::coordinator::filter_replayed_synced_sessions(&mut replay_entries, tunnel_purge_ids);
    let replayed_synced_sessions = coord.replay_synced_sessions(
        &replay_entries,
        worker_command_queues.as_ref(),
        session_map,
    );
    if replayed_synced_sessions > 0 {
        coord.last_reconcile_stage = ReconcileStage::ReplayedSynced {
            count: replayed_synced_sessions,
            workers: worker_command_queues.len(),
        };
    }
    worker_command_queues
}

/// #6240 phase: RESOLVER (best-effort, ATTEMPTED before worker launch). Spawn
/// the shared on-demand neighbor resolver so every worker's
/// `WorkerSharedDataplane::from_coord` captures a clone of the handle. Guarded
/// by `resolver.is_none()` so a re-reconcile reuses the existing thread. The
/// attempt is BEST-EFFORT: on spawn failure `coord.neighbors.resolver` stays
/// `None` and workers still launch (with `resolver: None`) — the invariant is
/// attempt-before-launch, NOT resolver-must-exist, so the resolver is NEVER
/// threaded into `spawn_workers` as a required input. Returns the resulting
/// handle (`Some` when installed/already-present, `None` when the spawn failed)
/// so the ordering/best-effort contract is directly unit-testable. Verbatim
/// move of the pre-#6240 inline block.
pub(in crate::afxdp) fn ensure_resolver(coord: &mut Coordinator) -> Option<Arc<NeighborResolver>> {
    // #1769: spawn the shared on-demand neighbor resolver BEFORE the
    // worker spawn loop so every worker captures a clone of the resolver
    // handle. Guarded like the monitor/warmer so a re-reconcile reuses
    // the existing thread. The resolver issues single-key RTM_GETNEIGH +
    // probe-on-stale off the hot path when a worker's negative-cache
    // fast-fail nudges a wedged dst.
    if coord.neighbors.resolver.is_none() {
        let (tx, rx) = mpsc::sync_channel::<ResolveItem>(
            super::super::neighbor_resolver::RESOLVER_QUEUE_DEPTH,
        );
        let resolver_stop = Arc::new(AtomicBool::new(false));
        let resolver_stop_clone = resolver_stop.clone();
        let dynamic_neighbors = coord.neighbors.dynamic.clone();
        let neighbor_generation = coord.neighbors.generation.clone();
        let neighbor_generation_handle = neighbor_generation.clone();
        let counters = coord.neighbors.resolver_counters.clone();
        let counters_clone = counters.clone();
        // #1772: latency telemetry shared into the resolver thread + the
        // worker-facing handle. `get_rtt_hist` is resolver-thread-only;
        // the dwell/drop/depth counters ride the worker-facing handle.
        let get_rtt_hist = coord.neighbors.resolver_get_rtt_hist.clone();
        let pending_dwell_hist = coord.neighbors.pending_dwell_hist.clone();
        let pending_timeout_drops = coord.neighbors.pending_timeout_drops.clone();
        let pending_max_depth = coord.neighbors.pending_max_depth.clone();
        // Retain the join handle so stop_inner can join the resolver and
        // enforce no-mutation-after-stop (the bare stop re-check is a
        // check-then-act race; joining is the real guard). Only install
        // the resolver handle when the thread actually spawned: on spawn
        // failure leave `resolver`/`resolver_stop`/`resolver_join` as
        // `None` so the NEXT reconcile retries (the `is_none()` guard
        // above stays true) and workers see `None` and skip on-demand
        // resolution — they never enqueue into a permanently-dead resolver
        // (Copilot). The dst still fast-fails normally; no availability
        // regression.
        match spawn_supervised_aux("neigh-resolver", move || {
            neighbor_resolver_loop(
                rx,
                dynamic_neighbors,
                neighbor_generation,
                counters_clone,
                get_rtt_hist,
                resolver_stop_clone,
            )
        }) {
            Ok(join) => {
                coord.neighbors.resolver = Some(Arc::new(NeighborResolver::new(
                    tx,
                    counters,
                    neighbor_generation_handle,
                    pending_dwell_hist,
                    pending_timeout_drops,
                    pending_max_depth,
                )));
                coord.neighbors.resolver_stop = Some(resolver_stop);
                coord.neighbors.resolver_join = Some(join);
            }
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: neighbor resolver thread spawn failed: {err}; \
                     on-demand resolution disabled this reconcile (will retry)"
                );
            }
        }
    }
    coord.neighbors.resolver.clone()
}

/// #6240 phase: SPAWN. The per-worker spawn loop — build the five typed #6241
/// launch bundles, spawn the worker thread (with the #925 panic slot + the
/// `#[cfg(test)]` force-failure seams), and on success register ONE #6242
/// post-spawn `WorkerRuntimeRecord`. Returns a typed [`LaunchOutcome`]:
/// `SpawnFailed` on the FIRST spawn failure (its stage already recorded on
/// `coord.last_reconcile_stage`; launched records left INTACT), else
/// `AllSpawned` with the spawned ids + dispatched planned-slot sets for the
/// readiness barrier.
///
/// #4952 (non-negotiable): this NEVER calls `stop_inner`. The two-armed rollback
/// DECISION lives in the [`bring_up_workers`] shell. The startup-report SENDER is
/// owned by the shell and passed BY REFERENCE (`startup_report_tx`); each worker
/// clones it. Verbatim move of the pre-#6240 inline spawn loop.
fn spawn_workers(
    coord: &mut Coordinator,
    workers: BTreeMap<u32, Vec<BindingPlan>>,
    node_id: u8,
    worker_command_queues: Arc<BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>>,
    dnat_fds: DnatTableFds,
    startup_report_tx: &mpsc::Sender<WorkerStartupReport>,
) -> LaunchOutcome {
    // #5143: per-worker STARTUP READINESS barrier. Each spawned worker reports
    // (over the shell-owned channel, after its in-thread binds) the set of
    // planned slots whose XSK actually bound. `planned_slots_by_worker` records
    // the set the reconcile DISPATCHED to each worker; `spawned_worker_ids` is
    // the set of workers whose spawn succeeded (only those are expected to
    // report). The shell's barrier waits for every spawned worker's report under
    // a bounded deadline and checks bound == planned — a heartbeat alone no
    // longer counts as ready.
    let mut planned_slots_by_worker: BTreeMap<u32, std::collections::BTreeSet<u32>> =
        BTreeMap::new();
    let mut spawned_worker_ids: Vec<u32> = Vec::new();
    for (worker_id, binding_plans) in workers {
        let plan_count = binding_plans.len();
        // #5143: the slot set this worker is REQUIRED to bind. Captured before
        // `binding_plans` is moved into the worker body so the barrier can
        // compare it against the worker's reported bound set.
        let planned_slots: std::collections::BTreeSet<u32> =
            binding_plans.iter().map(|plan| plan.status.slot).collect();
        // #8388: the per-slot `BindingLiveState` handles dispatched to this
        // worker, captured here because `binding_plans` is moved into the
        // launch plan below. Used ONLY by the `#[cfg(test)]` stub arms, which
        // publish `set_bound` through them for every slot they REPORT as bound
        // — the same publish a real `worker_loop` makes from
        // `BindingWorker::create`. Without it a "healthy" stub is healthy only
        // in its startup report: `refresh_bindings` reads the (never-published)
        // live state and every slot comes back `bound = false`, so the
        // operator- and Go-visible binding surface is IDENTICAL whether the
        // fail-close stopped the healthy siblings or not, and any cell over
        // that surface is mutation-insensitive by construction.
        #[cfg(test)]
        let stub_lives: BTreeMap<u32, Arc<BindingLiveState>> = binding_plans
            .iter()
            .map(|plan| (plan.status.slot, plan.live.clone()))
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let heartbeat = Arc::new(AtomicU64::new(monotonic_nanos()));
        let session_export_ack = Arc::new(AtomicU64::new(0));
        let cos_status = Arc::new(ArcSwap::from_pointee(Vec::new()));
        let commands = worker_command_queues
            .get(&worker_id)
            .cloned()
            .unwrap_or_else(|| Arc::new(Mutex::new(VecDeque::new())));
        // #5289: give each worker its OWN exception ring + last-resolution
        // slot so the ~1 Hz status thread can drain them. This replaces the
        // shared process-global `recent_exceptions`/`last_resolution` mutexes
        // whose cross-worker contention was the DoS. The per-worker mutex is
        // locked only by its owning worker plus the status reader — no
        // cross-worker false sharing.
        //
        // #6242: allocate each `Arc` ONCE, then RETAIN one clone for the
        // post-spawn-success runtime record (`record_exception_ring` /
        // `record_last_resolution`) and MOVE the original into
        // `WorkerPublishedTelemetry` (the worker-facing bundle takes them by
        // value below). Same allocation + live-worker ownership topology as
        // master — the record and the live worker share the alloc — but the
        // record is registered as ONE `records.insert` AFTER the spawn
        // succeeds, so there is no pre-spawn coordinator-map insert to unwind
        // on a spawn failure (the #4952 differential is structural).
        let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
        let record_exception_ring = recent_exceptions.clone();
        let last_resolution = Arc::new(Mutex::new(None));
        let record_last_resolution = last_resolution.clone();
        let recent_session_deltas = coord.recent_session_deltas.clone();
        let stop_clone = stop.clone();
        let heartbeat_clone = heartbeat.clone();
        let session_export_ack_clone = session_export_ack.clone();
        let commands_clone = commands.clone();
        let peer_commands_clone = worker_command_queues
            .iter()
            .filter(|(id, _)| **id != worker_id)
            .map(|(_, queue)| queue.clone())
            .collect::<Vec<_>>();
        let worker_commands_by_id = worker_command_queues.clone();
        let worker_poll_mode = coord.poll_mode;
        let event_stream_handle = coord.event_stream_worker_handle();
        let cos_status_clone = cos_status.clone();
        let runtime_atomics =
            std::sync::Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new());
        let runtime_atomics_clone = runtime_atomics.clone();
        // #1621: sibling per-worker WorkerColdPathAtomics, allocated
        // alongside the runtime_atomics so the publish + snapshot
        // contract is symmetric across the two seqlocks (window_gen +
        // cold_window_gen). Worker thread writes via
        // publish_from_local() each ~1s tick; coordinator status path
        // reads via snapshot() at each /metrics scrape.
        let cold_path_atomics =
            std::sync::Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new());
        let cold_path_atomics_clone = cold_path_atomics.clone();
        // #925 Phase 1: per-worker panic slot, keyed by worker_id.
        // #6242: retain ONE clone (`record_panic`) for the post-spawn-success
        // runtime record and pass a clone into `spawn_supervised_worker` (its
        // catch_unwind closure owns it, `supervisor.rs`). Same allocation +
        // live-worker ownership topology as master — the record holds the same
        // `Arc` the supervisor closure writes the panic payload into. No
        // pre-spawn coordinator-map insert, so the spawn-Err arm has nothing to
        // `.remove` (the #4952 differential is structural).
        let panic_slot = Arc::new(Mutex::new(None::<String>));
        let record_panic = panic_slot.clone();
        // #5143: the worker's end of the startup-readiness channel. Moved into
        // the worker body; `worker_loop` sends the achieved bound-slot set on
        // it after setup, before entering the steady loop.
        let startup_report_tx_worker = startup_report_tx.clone();
        // #6241: assemble the typed worker-launch bundles via their
        // `from_coord` / `new` builders (NOT inline struct literals), so a
        // same-typed source swap is caught by the `Arc::ptr_eq` wiring
        // tests in worker/launch.rs. `WorkerSharedDataplane::from_coord`
        // and `WorkerCoSState::from_coord` perform exactly the
        // `coord.*.clone()` calls this closure used to inline — one
        // `Arc::clone` per field, no extra allocation. The bundles borrow
        // `coord` HERE and are then MOVED into the worker body, which
        // never touches `coord` (it must be 'static for the spawn).
        let launch_plan =
            WorkerLaunchPlan::new(worker_id, node_id, binding_plans, worker_poll_mode, dnat_fds);
        let shared_dataplane = WorkerSharedDataplane::from_coord(coord);
        let control_channels = WorkerControlChannels::new(
            commands_clone,
            peer_commands_clone,
            worker_commands_by_id,
            stop_clone,
            heartbeat_clone,
            session_export_ack_clone,
            event_stream_handle,
            startup_report_tx_worker,
        );
        let cos_state = WorkerCoSState::from_coord(coord);
        let published_telemetry = WorkerPublishedTelemetry::new(
            recent_exceptions,
            recent_session_deltas,
            last_resolution,
            cos_status_clone,
            runtime_atomics_clone,
            cold_path_atomics_clone,
        );
        let body = move || {
            worker_loop(
                launch_plan,
                shared_dataplane,
                control_channels,
                cos_state,
                published_telemetry,
            );
        };
        // #4952 test seam: force the fallible worker spawn to fail so the
        // post-teardown fail-closed propagation is unit-verifiable without a
        // real (unprovokable) pthread_create EAGAIN/ENOMEM. Declines the real
        // spawn, drops the worker body unspawned, and synthesizes the same
        // `std::io::Error` a resource-exhausted spawn returns. Always 0 in
        // release builds (`force_worker_spawn_fail` is `#[cfg(test)]`).
        //
        // #5143 test seam: force a SPAWNED worker to report an INCOMPLETE
        // startup bound-slot set (a worker whose in-thread XSK/UMEM bind failed
        // for one or more planned bindings but keeps heartbeating). A real
        // `worker_loop` cannot bind a real XSK in-process, so instead spawn a
        // joinable STUB thread that reports a bound set MISSING one planned
        // slot, then heartbeats until stopped — exercising the readiness
        // barrier's fail-close + stop/join end to end. Checked BEFORE the
        // spawn-fail seam so the two are mutually exclusive per worker.
        #[cfg(test)]
        let join = if coord.force_worker_bind_incomplete > 0 {
            coord.force_worker_bind_incomplete -= 1;
            drop(body);
            // Report every planned slot EXCEPT one (`skip(1)`), so with a
            // single planned binding the reported set is empty and with N it
            // is short by one — either way bound != planned -> barrier fails
            // closed.
            let incomplete_bound: Vec<u32> = planned_slots.iter().copied().skip(1).collect();
            // #8388: publish the bound live state for the slots this stub
            // reports bound. Synchronous (before the spawn) rather than inside
            // the stub body so the surface is race-free: the `SpawnFailed` arm
            // returns without ever reaching the readiness barrier, so a
            // stub-thread publish would not be ordered against the reconcile's
            // closing `refresh_bindings`.
            for slot in &incomplete_bound {
                if let Some(live) = stub_lives.get(slot) {
                    live.set_bound(-1);
                }
            }
            // #6245: the omitted slot is the SMALLEST planned slot (`skip(1)`
            // drops the first of the sorted BTreeSet). Report it as an EXPLICIT
            // per-slot failure so the barrier surfaces the cause, exercising the
            // #6245 explicit-failure contract end-to-end (a real `worker_loop`
            // cannot bind an XSK in-process). Empty when no slots are planned.
            let stub_failures: Vec<BindingSetupFailure> = planned_slots
                .iter()
                .copied()
                .next()
                .map(|slot| BindingSetupFailure {
                    slot,
                    interface: "ge-0-0-1".to_string(),
                    queue_id: slot,
                    phase: BindingSetupPhase::Private,
                    // #8558: shaped like the real `bind.rs` failure text so the
                    // cause a cell reads back is the cause production
                    // publishes — including the "Device or resource busy"
                    // substring `hasBusyBindingsWedgeLocked` keys on. The
                    // original seam wording is retained verbatim inside it, so
                    // the #6245 stage-rendering cell that pins that phrase is
                    // unaffected.
                    reason: "libxdp private bind(flags=0x0004): Device or resource \
busy — forced private bind failure (test seam #6245)"
                        .to_string(),
                })
                .into_iter()
                .collect();
            // #8558: mirror `worker_loop_setup`'s `live.set_error(reason)` on
            // the slot whose bind failed. The stub is the only in-process stand
            // -in for a real bind failure, and a stub that reports the shortfall
            // without publishing the cause into its `BindingLiveState` would let
            // a fix that reads the cause from `live` (rather than from the
            // fail-closed stage) look correct here while doing nothing in
            // production — `stop_inner` drops `live` before anything reads it.
            for failure in &stub_failures {
                if let Some(live) = stub_lives.get(&failure.slot) {
                    live.set_error(failure.reason.clone());
                }
            }
            let stub_stop = stop.clone();
            let stub_heartbeat = heartbeat.clone();
            let stub_tx = startup_report_tx.clone();
            let stub_worker_id = worker_id;
            spawn_supervised_worker(
                worker_id,
                runtime_atomics.clone(),
                panic_slot,
                move || {
                    let _ = stub_tx.send(WorkerStartupReport {
                        worker_id: stub_worker_id,
                        bound_slots: incomplete_bound,
                        binding_failures: stub_failures,
                        recovered_fallbacks: Vec::new(),
                    });
                    // Heartbeat while "live-but-unbound" until the barrier
                    // stops us — bounded so a REVERTED (barrier removed) build
                    // does not leak a thread forever.
                    let mut ticks = 0u32;
                    while !stub_stop.load(std::sync::atomic::Ordering::Relaxed) && ticks < 5_000 {
                        stub_heartbeat.store(monotonic_nanos(), std::sync::atomic::Ordering::Relaxed);
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        ticks += 1;
                    }
                },
            )
        } else if coord.force_worker_spawn_fail > 0 && coord.force_worker_spawn_fail_skip == 0 {
            // #4952 / #6242: the forced spawn failure fires once the skip credit
            // is exhausted. With `force_worker_spawn_fail_skip == 0` (the #4952
            // default) this fails the FIRST planned worker; with a positive skip
            // it fails the `(skip+1)`th, after the first `skip` workers launched
            // (as healthy stubs, below) — exercising PARTIAL-success rollback.
            coord.force_worker_spawn_fail -= 1;
            drop(body);
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "forced worker spawn failure (test seam #4952/#6242)",
            ))
        } else if coord.force_worker_healthy_stub {
            // #6242: benign HEALTHY stub — reports the FULL planned bound set so
            // the readiness barrier passes, then heartbeats until stopped. Used
            // to launch the workers that PRECEDE a fail-at-K spawn failure (or
            // that coexist with a single bind-incomplete worker) WITHOUT running
            // the real `worker_loop`, which cannot bind a real XSK in-process.
            // When skipping toward a forced failure, consume one skip credit so
            // the failure fires on the intended Kth worker.
            if coord.force_worker_spawn_fail > 0 && coord.force_worker_spawn_fail_skip > 0 {
                coord.force_worker_spawn_fail_skip -= 1;
            }
            drop(body);
            let full_bound: Vec<u32> = planned_slots.iter().copied().collect();
            // #8388: see the sibling publish in the bind-incomplete arm. A
            // HEALTHY stub reports its full planned set, so it publishes bound
            // live state for all of it — that is what makes "the fail-close
            // stopped the healthy siblings too" observable on the binding
            // surface instead of only in `workers.records`.
            for slot in &full_bound {
                if let Some(live) = stub_lives.get(slot) {
                    live.set_bound(-1);
                }
            }
            let stub_stop = stop.clone();
            let stub_heartbeat = heartbeat.clone();
            let stub_tx = startup_report_tx.clone();
            let stub_worker_id = worker_id;
            spawn_supervised_worker(worker_id, runtime_atomics.clone(), panic_slot, move || {
                let _ = stub_tx.send(WorkerStartupReport {
                    worker_id: stub_worker_id,
                    bound_slots: full_bound,
                    binding_failures: Vec::new(),
                    recovered_fallbacks: Vec::new(),
                });
                let mut ticks = 0u32;
                while !stub_stop.load(std::sync::atomic::Ordering::Relaxed) && ticks < 5_000 {
                    stub_heartbeat
                        .store(monotonic_nanos(), std::sync::atomic::Ordering::Relaxed);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    ticks += 1;
                }
            })
        } else {
            spawn_supervised_worker(worker_id, runtime_atomics.clone(), panic_slot, body)
        };
        #[cfg(not(test))]
        let join = spawn_supervised_worker(worker_id, runtime_atomics.clone(), panic_slot, body);
        match join {
            Ok(join) => {
                eprintln!(
                    "xpf-userspace-dp: started worker thread worker_id={} planned_bindings={}",
                    worker_id, plan_count
                );
                // #5143: this worker spawned, so it is EXPECTED to report its
                // startup bound-slot set; record its dispatched plan for the
                // barrier's bound-vs-planned check below.
                planned_slots_by_worker.insert(worker_id, planned_slots);
                spawned_worker_ids.push(worker_id);
                // #6242: registration is ONE `records.insert` AFTER the spawn
                // succeeded. The record consolidates the worker's handle plus
                // its three observability `Arc`s (panic / exception ring /
                // last-resolution) — the same allocations the worker telemetry
                // and the supervisor closure hold. "Registered" now type-level
                // means "spawn succeeded and all four owners exist"; a failed
                // worker never reaches here, so its locals just drop (the #4952
                // differential: launched records are never touched).
                // #7209: ONE `register` call publishes the record and takes
                // ownership of the join handle. The handle no longer rides
                // inside `WorkerHandle` — consuming it needed `&mut` on the
                // record, which is the only thing that stopped the record from
                // being publishable behind an `Arc` for the off-lock import
                // path. `WorkerManager::stop_and_clear` still joins it, in the
                // same signal-all-then-join-all order.
                coord.workers.register(
                    worker_id,
                    WorkerRuntimeRecord {
                        handle: WorkerHandle {
                            stop,
                            heartbeat,
                            commands,
                            session_export_ack,
                            cos_status,
                            runtime_atomics,
                            cold_path_atomics,
                        },
                        panic: record_panic,
                        exception_ring: record_exception_ring,
                        last_resolution: record_last_resolution,
                    },
                    Some(join),
                );
            }
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: failed to start worker thread worker_id={} err={}",
                    worker_id, err
                );
                let stage = ReconcileStage::SpawnWorkerFailed {
                    worker_id,
                    err: err.to_string(),
                };
                coord.last_reconcile_stage = stage.clone();
                // #6242: registration is POST-spawn-success, so a FAILED worker
                // never had a record — there is nothing to unwind. The
                // pre-#6242 layout inserted the panic slot (#925) + exception
                // ring / last-resolution slot (#5289) BEFORE spawn and had to
                // `.remove(&worker_id)` all three here; those removes are gone.
                // The record's `Arc` locals (`record_panic` /
                // `record_exception_ring` / `record_last_resolution`) simply
                // drop at end of this loop iteration. LAUNCHED workers' records
                // are untouched (the #4952 differential — they are reclaimed by
                // the next reconcile's teardown).
                if let Ok(mut recent) = coord.recent_exceptions.lock() {
                    // #6244: the control notice still carries the byte-identical
                    // legacy stage string (rendered from the typed stage), so
                    // the operator-facing notice is unchanged.
                    push_recent_exception(&mut recent, control_notice_event("", stage.to_string()));
                }
                // #4952: a spawn failed on the POST-TEARDOWN destructive
                // path — the old workers are gone, so this queue set now has
                // NO XSK-bound worker (silent forwarding outage). ABORT the
                // remaining launches (the data plane is already broken;
                // spawning more XSK-bound workers cannot restore forwarding
                // and only compounds the resource pressure) and return the
                // preserved stage so the shell returns Err and the caller
                // fails closed instead of persisting a broken snapshot.
                // #4952/#6240: NEVER `stop_inner` here — the launched workers'
                // records are left INTACT; the two-armed rollback decision is
                // made by the shell.
                return LaunchOutcome::SpawnFailed(stage);
            }
        }
    }
    LaunchOutcome::AllSpawned {
        spawned_worker_ids,
        planned_slots_by_worker,
    }
}

/// #6240 phase: POST-READINESS neighbor services + the local tunnel/WG
/// reconcile. Runs ONLY after the #5143 readiness barrier passes (every worker
/// bound its full planned set): start the helper-owned neighbor monitor +
/// warmer (each guarded so a re-reconcile reuses the existing thread), then run
/// the #1881 three-pass local tunnel-source reconcile + the WireGuard control
/// threads. Verbatim move of the pre-#6240 inline block.
fn start_post_readiness_neighbor_services(coord: &mut Coordinator) {
    // Start the helper-owned neighbor sync path. It does an initial
    // RTM_GETNEIGH dump so startup sees the existing kernel table, then
    // subscribes to RTM_{NEW,DEL}NEIGH for incremental updates.
    if coord.neighbors.monitor_stop.is_none() {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let dynamic_neighbors = coord.neighbors.dynamic.clone();
        let neighbor_generation = coord.neighbors.generation.clone();
        // #1771 §2.6: ENOBUFS/re-dump telemetry rides the shared
        // resolver-counter block (same status wire path).
        let monitor_counters = coord.neighbors.resolver_counters.clone();
        // #925-A: wrap aux thread in catch_unwind so a panic in the
        // netlink path doesn't kill the daemon. No respawn — see
        // spawn_supervised_aux doc for operator-visible degradation.
        //
        // #5165: RETAIN the join handle (was discarded via `.ok()`), mirroring
        // the sibling `neigh-resolver` above. Install `monitor_stop` +
        // `monitor_join` together ONLY when the thread actually spawned, so
        // `stop_inner` can JOIN the monitor after signalling stop and enforce
        // no-mutation-after-stop. On spawn failure leave BOTH `None` so the
        // `monitor_stop.is_none()` guard above lets the NEXT reconcile retry —
        // the neighbor cache still fills from the workers' RX-learned path and
        // the on-demand resolver, so there is no availability regression.
        match spawn_supervised_aux("neigh-monitor", move || {
            neigh_monitor_thread(
                stop_clone,
                dynamic_neighbors,
                neighbor_generation,
                monitor_counters,
            )
        }) {
            Ok(join) => {
                coord.neighbors.monitor_stop = Some(stop);
                coord.neighbors.monitor_join = Some(join);
            }
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: neighbor monitor thread spawn failed: {err}; \
                     kernel neighbor sync disabled this reconcile (will retry)"
                );
            }
        }
    }
    // #1636 option C: spawn the long-lived neighbor-warmer worker. Fed
    // by Coordinator::queue_warm_pass via a bounded MPSC queue; fires
    // ARP/NDP solicits for configured next-hops off the hot path so the
    // neighbor cache is warm before the first user flow.
    if coord.neighbors.warm_queue.is_none() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(WARM_QUEUE_DEPTH);
        let warm_stop = Arc::new(AtomicBool::new(false));
        let warm_stop_clone = warm_stop.clone();
        let last_probed = coord.neighbors.last_probed_at.clone();
        let warm_generation = coord.neighbors.warm_generation.clone();
        let rg_runtime = coord.ha.rg_runtime.clone();
        // #6314: RETAIN the warmer's join handle (was discarded via `.ok()`,
        // the pre-#5165 pattern the monitor + resolver siblings already left
        // behind). Install `warm_queue` + `warm_stop` + `warm_join` together
        // ONLY when the thread actually spawned, so `stop_inner` can JOIN the
        // warmer after signalling stop and dropping the producer and enforce
        // no-mutation-after-stop. On spawn failure (EAGAIN/ENOMEM) log it —
        // previously `.ok()` SWALLOWED the error, silently never running the
        // warmer — and leave ALL THREE `None` so the `warm_queue.is_none()`
        // guard above lets the NEXT reconcile retry. Warming is best-effort
        // (the neighbor cache still fills from the workers' RX-learned path and
        // the on-demand resolver), so there is no availability regression.
        match spawn_supervised_aux("neigh-warmer", move || {
            neighbor_warmer_loop(
                rx,
                last_probed,
                warm_generation,
                rg_runtime,
                warm_stop_clone,
            )
        }) {
            Ok(join) => {
                coord.neighbors.warm_queue = Some(tx);
                coord.neighbors.warm_stop = Some(warm_stop);
                coord.neighbors.warm_join = Some(join);
            }
            Err(err) => {
                eprintln!(
                    "xpf-userspace-dp: neighbor warmer thread spawn failed: {err}; \
                     proactive neighbor warming disabled this reconcile (will retry)"
                );
            }
        }
    }
    // #1881: three-pass reconcile (degenerates to pure spawn here —
    // stop_inner cleared the entry map before this bring-up, and the
    // worker spawn loop above populated `workers.records`, satisfying
    // the spawn-pass worker gate).
    coord.reconcile_local_tunnel_sources();
    coord.spawn_wg_control_threads();
}

/// #5143: the STARTUP READINESS BARRIER. Wait for every SPAWNED worker to
/// report the slot set its in-thread XSK/UMEM binds actually brought up, under
/// a bounded deadline ([`WORKER_STARTUP_BARRIER_TIMEOUT_NS`]), then check
/// `bound == planned` for each. Returns `None` when every worker bound its full
/// planned set (the reconcile may proceed), or `Some(stage)` — the typed
/// [`ReconcileStage::WorkerBindIncomplete`] identity — on the FIRST worker that
/// bound a partial/empty set OR never reported in time (fail closed).
///
/// #6240: the shell owns the two-armed rollback DECISION — this barrier only
/// COMPUTES the verdict (it never calls `stop_inner`); the shell calls
/// `stop_inner(false)` on `Some(stage)`.
///
/// The barrier does NOT block forever: it stops waiting at the deadline and
/// treats any worker with no report as failed. A worker that finished setup
/// with a partial binding set reports IMMEDIATELY (the common failure), so this
/// returns fast without approaching the deadline; only a worker that
/// hangs/dies inside setup consumes the full budget. Reads a moved-value report
/// off the channel — no shared mutable state, so the channel's send→recv
/// establishes the happens-before for the reported set.
/// #8558: re-record the TERMINAL per-slot bind-failure causes a fail-closed
/// bring-up produced, so `Coordinator::refresh_bindings` can re-publish them
/// into `BindingStatus::last_error` on every subsequent status refresh.
///
/// Extracted rather than inlined in the `BindIncomplete` arm because the
/// SELECTION — which slots get which reason — is the part a guard has to bind.
/// Inline it and the only thing a cell can reach is the arm as a whole.
///
/// Scope is deliberately the EXPLICIT failures only (#6245's per-slot
/// `BindingSetupFailure`). The timeout / no-report shortfall (`bound: None`)
/// carries no per-slot cause to attribute, and inventing one would put a
/// reason on slots that may well have bound. That sub-case therefore still
/// reaches the Go wedge predicate with an empty `last_error`, and recovery
/// still does not fire for it — widening the predicate to cover a wedge whose
/// cause is unknown is a separate decision, because the `maxConsecutiveAuto
/// Rebinds` derivation assumes the rebind is being fired for a teardown race.
fn record_bind_failure_causes(coord: &mut Coordinator, stage: &ReconcileStage) {
    let ReconcileStage::WorkerBindIncomplete(shortfall) = stage else {
        return;
    };
    for failure in &shortfall.failures {
        coord
            .last_bind_failures
            .insert(failure.slot, failure.reason.clone());
    }
}

fn await_readiness(
    startup_report_rx: &mpsc::Receiver<WorkerStartupReport>,
    spawned_worker_ids: &[u32],
    planned_slots_by_worker: &BTreeMap<u32, std::collections::BTreeSet<u32>>,
) -> Option<ReconcileStage> {
    if spawned_worker_ids.is_empty() {
        return None;
    }
    // Collect one report per spawned worker (last write wins per id) until we
    // have them all or the deadline elapses.
    let deadline_ns = monotonic_nanos().saturating_add(WORKER_STARTUP_BARRIER_TIMEOUT_NS);
    // #6245: retain the FULL report (not just the bound-slot set) so a
    // shortfall can be attributed to its EXPLICIT per-slot failure(s) rather
    // than inferred from the missing slots alone.
    let mut report_by_worker: BTreeMap<u32, WorkerStartupReport> = BTreeMap::new();
    while report_by_worker.len() < spawned_worker_ids.len() {
        let now = monotonic_nanos();
        if now >= deadline_ns {
            break;
        }
        match startup_report_rx.recv_timeout(std::time::Duration::from_nanos(deadline_ns - now)) {
            Ok(report) => {
                report_by_worker.insert(report.worker_id, report);
            }
            // Timed out with reports still outstanding, or every sender was
            // dropped (a worker panicked in setup before reporting). Either
            // way the missing worker(s) are treated as failed below.
            Err(mpsc::RecvTimeoutError::Timeout)
            | Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    for &worker_id in spawned_worker_ids {
        let planned = planned_slots_by_worker
            .get(&worker_id)
            .cloned()
            .unwrap_or_default();
        // #6245 composed onto #6244's typed stage: retain the FULL report so a
        // shortfall carries its EXPLICIT per-slot binding failures. The typed
        // `WorkerBindShortfall` now owns `failures`; the stage's `Display`
        // renders them (empty -> `failures=[no-explicit-failure]`).
        match report_by_worker.get(&worker_id) {
            Some(report) => {
                let bound: std::collections::BTreeSet<u32> =
                    report.bound_slots.iter().copied().collect();
                if bound == planned {
                    continue;
                }
                // A shortfall — surface the EXPLICIT cause. The report's
                // `binding_failures` carries the slot + phase + owned error for
                // each terminal bind failure that produced the shortfall (empty
                // only if a slot went missing without a recorded failure, which
                // the renderer flags as `no-explicit-failure`).
                return Some(ReconcileStage::WorkerBindIncomplete(WorkerBindShortfall {
                    worker_id,
                    bound: Some(bound.len()),
                    planned: planned.len(),
                    failures: report.binding_failures.clone(),
                }));
            }
            None => {
                // No report before the deadline (timeout / setup panic). There
                // is no explicit per-slot failure to attribute — empty.
                return Some(ReconcileStage::WorkerBindIncomplete(WorkerBindShortfall {
                    worker_id,
                    bound: None,
                    planned: planned.len(),
                    failures: Vec::new(),
                }));
            }
        }
    }
    None
}

/// #1830 follow-up (Codex review on PR #1841): array length needed to
/// index every planned worker id — `max(worker_id) + 1`, 0 when no
/// workers are planned. NOT the worker count: ids can be sparse after
/// partial binding unregister (the bring-up loop skips
/// unregistered/invalid bindings), and the v8 lease contract
/// (`SharedCoSQueueLease::new_v8`) requires the TRUE max id so its
/// per-worker arrays and rotation scratch cover every live worker.
/// Generic over the map value so the sparse-id derivation is unit
/// testable without constructing `BindingPlan`s.
pub(in crate::afxdp) fn planned_worker_slots<V>(workers: &BTreeMap<u32, V>) -> usize {
    workers
        .keys()
        .next_back()
        .map(|&id| id as usize + 1)
        .unwrap_or(0)
}
