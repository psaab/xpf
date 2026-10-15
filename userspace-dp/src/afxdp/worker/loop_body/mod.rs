// #1326 — extracted from worker/mod.rs (pure code motion).
// The `worker_loop` per-tick orchestrator was previously a ~1278 LOC
// function in worker/mod.rs (L995-L2273), moved here verbatim as the
// first phase of the #1326 refactor.
//
// #1776 (Phase 2, narrowed v3.1 scope) carved out the two cold
// extractions: the one-shot setup phase (setup.rs) and the
// cfg(debug-log) verbose report / stall dump (debug_report.rs).
// Everything per-tick — telemetry publish, ArcSwap config refresh,
// HA load, command drain, the hot `poll_binding` sweep, heartbeat,
// the always-on binding diagnostics + BindingLiveState publish, and
// idle regulation — deliberately stays INLINE in this file: the
// round-1 plan review (Codex r1-4) established that an
// #[inline(never)] call boundary in front of the per-tick
// `load_arc_if_changed` path risks regressing the 10K-100K ticks/s
// loop.
//
// #6291/#6592 carve-out: the per-tick path does now call one helper,
// `refresh_runtime_view`, which exists to pin the SINGLE-load property
// of the (validation, forwarding) pair and to expose a
// controlled-interleaving test seam. It is `#[inline]` and its
// production `between` argument is `|| {}` (a ZST whose `call_once`
// body is empty), so it leaves NO call boundary in release: the
// symbol is absent from `nm` on a `cargo build --release` binary
// while its caller `worker_loop` is present, and the seam emits no
// instructions. The no-inline-boundary constraint above still binds
// for anything that would survive as a real call.
//
// `use super::*;` brings every type, helper, and sibling-submodule
// item from worker/mod.rs into scope — the same pattern lifecycle.rs
// and cos.rs use. Pure relocation — no production logic touched.

use super::*;
use crate::afxdp::ipsec_inner::{
    IpsecInnerAdvisory, IpsecInnerInput, adjudicate_descriptor, verdict_from_decision,
};
use crate::afxdp::ipsec_inner_queue::{
    IPSEC_INNER_DRAIN_BUDGET, IpsecInnerDoubleBatch, IpsecInnerVerdict, reason as ipsec_reason,
};
use crate::slowpath_reinject_9506::{ReinjectLease, SUBMIT_FLAG_FORWARD};
// #1776: the one-shot setup phase (thread pin, TSC calibration,
// initial ArcSwap load_fulls, binding construction, BPF-map-FD
// cache, initial cos_status publish) lives in loop_body/setup.rs.
mod setup;
mod screen_status;

// #1776: the cfg(debug-log) verbose per-second report + stall dump +
// per-interval DbgCounters live in loop_body/debug_report.rs. The
// module is feature-gated at the declaration so release builds
// compile none of it.
#[cfg(feature = "debug-log")]
mod debug_report;

// #6431: classification of the Interrupt-mode idle-regulation `poll(2)`
// return. Idle path only — it does not sit on the per-tick hot path the
// no-call-boundary note above constrains.
mod idle_poll;

#[cfg(test)]
#[path = "first_policy_purge_rotation_9526_tests.rs"]
mod first_policy_purge_rotation_9526_tests;

#[cfg(test)]
#[path = "expiry_shared_retire_10419_tests.rs"]
mod expiry_shared_retire_10419_tests;

#[cfg(test)]
#[path = "bpf_ok_teardown_10590_tests.rs"]
mod bpf_ok_teardown_10590_tests;

#[cfg(test)]
#[path = "p2_deadline_9506_tests.rs"]
mod p2_deadline_9506_tests;

// #13075 (D4-12): cold snapshot-rotation reconciliation (discriminator,
// ancestry matchers, rematch/rebind walkers, the #6291/#6592 refresh seam,
// #9856 export state) lives in reconcile.rs. `pub(super) use` keeps every
// name resolving exactly as when it was defined inline here — including
// for the sibling test modules (`use super::*`).
mod reconcile;
pub(in crate::afxdp) use reconcile::*;

// #13075 (D4-12): session expiry / GC teardown helpers and the #10591
// production test seams live in gc_teardown.rs, re-exported the same way.
mod gc_teardown;
pub(in crate::afxdp) use gc_teardown::*;

// #13075 (D4-12): per-tick session expiry/GC housekeeping extracted from
// `worker_loop` (housekeeping.rs). Loop-local; no re-export needed.
mod housekeeping;
use housekeeping::run_session_housekeeping;

// #13075 (D4-12): #9856 CommandExport slice + steady-state delta drain
// extracted from `worker_loop` (export_slice.rs). Loop-local.
mod export_slice;
use export_slice::run_export_slice;

// #13075 (D4-12): delta-loss resync + stale-session sweeps extracted
// from `worker_loop` (delta_recovery.rs). Loop-local.
mod delta_recovery;
use delta_recovery::run_delta_recovery;

// #13075 (D4-12): PPTP control-inbox drain extracted from `worker_loop`
// (pptp_drain.rs). Loop-local.
mod pptp_drain;
use pptp_drain::run_pptp_control_drain;

// #13075 (D4-12): conntrack-refresh slice + fabric/WG drains extracted
// from `worker_loop` (ct_slice.rs). Loop-local.
mod ct_slice;
use ct_slice::run_ct_slice;

// #13075 (D4-12): delta-loss resync + stale-session sweeps extracted
// from `worker_loop` (delta_recovery.rs). Loop-local.

// #13075 (D4-12): PPTP control-inbox drain extracted from `worker_loop`
// (pptp_drain.rs). Loop-local.

// #13075 (D4-12): conntrack-refresh slice + fabric/WG drains extracted
// from `worker_loop` (ct_slice.rs). Loop-local.

// #13075 (D4-12): the 1,243 LOC of inline #[cfg(test)] modules that used
// to trail this file live in tests.rs (excluded from the audit LOC count
// by the *_tests.rs/tests.rs filename shapes, docs/refactoring-audit.md).
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

// #13075: `flush_drained_session_deltas!` as a plain fn (it was a
// loop-local `macro_rules!` inside `worker_loop`; extracted fns in
// housekeeping.rs / export_slice.rs cannot name a loop-local macro, and
// the loop's own remaining call sites use this fn directly — one flush
// path, including the #2874 delta-loss latch, not two). The #2669
// rationale stands: the drain already popped the deltas off the ring
// PERMANENTLY, so the flush MUST run regardless of whether a binding
// exists; only the per-binding RPC fallback push is gated on a binding.
// When `bindings` is empty we synthesize a binding identity (labels
// only — no XSK) and fall back to the loop-cached map fds (which are
// `-1`, making the live session-map delete a harmless EBADF no-op).
#[allow(clippy::too_many_arguments)]
fn flush_session_deltas_loop(
    sessions: &mut crate::session::SessionTable,
    bindings: &[BindingWorker],
    session_map: crate::afxdp::bpf_map::SteeringMap<'_>,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    dnat_fds: &crate::afxdp::checksum::DnatTableFds,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    recent_session_deltas: &Arc<Mutex<VecDeque<crate::protocol::SessionDeltaInfo>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    worker_commands_by_id: &std::collections::BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
    event_stream: &Option<crate::event_stream::EventStreamWorkerHandle>,
    forwarding: &ForwardingState,
    shared_runtime: &RuntimeViewReader,
    worker_lossless_wedged: &mut bool,
    worker_id: u32,
    deltas: &[SessionDelta],
) {
    let event_stream_out_of_sync = match bindings.first() {
        Some(binding) => {
            let ident = binding.identity();
            flush_session_deltas(
                &ident,
                Some(&binding.live),
                binding.bpf_maps.session_map.handle(),
                conntrack_v4_fd,
                conntrack_v6_fd,
                dnat_fds,
                deltas,
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                shared_owner_rg_indexes,
                recent_session_deltas,
                peer_worker_commands,
                worker_commands_by_id,
                event_stream,
                forwarding,
                shared_runtime,
                &mut *worker_lossless_wedged,
                Some(&mut *sessions),
            )
        }
        None => {
            let ident = BindingIdentity {
                slot: 0,
                queue_id: 0,
                worker_id,
                interface: Arc::<str>::from(""),
                ifindex: -1,
            };
            flush_session_deltas(
                &ident,
                None,
                session_map,
                conntrack_v4_fd,
                conntrack_v6_fd,
                dnat_fds,
                deltas,
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                shared_owner_rg_indexes,
                recent_session_deltas,
                peer_worker_commands,
                worker_commands_by_id,
                event_stream,
                forwarding,
                shared_runtime,
                &mut *worker_lossless_wedged,
                Some(&mut *sessions),
            )
        }
    };
    if event_stream_out_of_sync {
        sessions.set_delta_loss();
    }
}

pub(crate) fn worker_loop(
    plan: WorkerLaunchPlan,
    shared: WorkerSharedDataplane,
    control: WorkerControlChannels,
    cos_state: WorkerCoSState,
    telemetry: WorkerPublishedTelemetry,
) {
    // #6241: destructure each typed launch bundle back into the EXACT
    // same local variable names the loop body uses today, BEFORE the
    // one-shot setup call below runs. From here down, the setup call and
    // the steady per-tick loop body are TEXTUALLY UNCHANGED — the bundles
    // are MOVED in and consumed here with zero added clone / alloc /
    // reference-indirection, and nothing bundle-shaped survives into the
    // hot 10K–100K-tick/s loop (the #1776 no-inline-boundary constraint).
    // The `runtime_atomics` (#869) / `cold_path_atomics` (#1621) publish
    // slots, the `startup_report_tx` (#5143) one-shot readiness channel,
    // and the #6242 telemetry lifecycle contract are documented on the
    // bundle fields in worker/launch.rs.
    let WorkerLaunchPlan {
        worker_id,
        node_id,
        binding_plans,
        poll_mode,
        dnat_fds,
    } = plan;
    let WorkerSharedDataplane {
        runtime: shared_runtime,
        ha_state,
        local_tunnel_deliveries,
        wg_uncovered_queues,
        fabrics: shared_fabrics,
        mirror_targets: shared_mirror_targets,
        rg_epochs,
        slow_path,
        neighbors:
            WorkerNeighbors {
                dynamic: dynamic_neighbors,
                resolver: neighbor_resolver,
            },
        sessions:
            WorkerSharedSessions {
                synced: shared_sessions,
                nat: shared_nat_sessions,
                forward_wire: shared_forward_wire_sessions,
                owner_rg_indexes: shared_owner_rg_indexes,
            },
        ike_exchanges,
        pptp_control,
    } = shared;
    let WorkerControlChannels {
        commands,
        peer_worker_commands,
        worker_commands_by_id,
        stop,
        heartbeat,
        session_export_ack,
        // #9856 M2c: the multi-pass cursor drives this (control leg).
        export_buffer,
        event_stream,
        startup_report_tx,
    } = control;
    let WorkerCoSState {
        cos_owner_worker_by_queue: shared_cos_owner_worker_by_queue,
        cos_owner_live_by_queue: shared_cos_owner_live_by_queue,
        cos_root_leases: shared_cos_root_leases,
        cos_exact_backlogs: shared_cos_exact_backlogs,
        cos_queue_leases: shared_cos_queue_leases,
        cos_queue_vtime_floors: shared_cos_queue_vtime_floors,
    } = cos_state;
    let WorkerPublishedTelemetry {
        recent_exceptions,
        recent_session_deltas,
        last_resolution,
        cos_status,
        runtime_atomics,
        cold_path_atomics,
    } = telemetry;
    // #1776: one-shot setup moved verbatim to setup.rs. The returned
    // WorkerLoopSetup is destructured into the same-named locals so
    // the loop body below is textually unchanged.
    let setup::WorkerLoopSetup {
        ha_startup_grace_until_secs,
        mut validation,
        mut forwarding,
        mut cos_owner_worker_by_queue,
        mut cos_owner_live_by_queue,
        mut cos_shared_root_leases,
        mut cos_shared_exact_backlogs,
        mut cos_shared_queue_leases,
        mut cos_shared_queue_vtime_floors,
        mut mirror_targets,
        mut sessions,
        mut screen_state,
        mut bindings,
        binding_lookup,
        mut interrupt_poll_fds,
        session_map,
        conntrack_v4_fd,
        conntrack_v6_fd,
        mut last_cos_status_ns,
        binding_failures,
        recovered_fallbacks,
    } = setup::worker_loop_setup(
        worker_id,
        node_id,
        binding_plans,
        &shared_runtime,
        &shared_cos_owner_worker_by_queue,
        &shared_cos_owner_live_by_queue,
        &shared_cos_root_leases,
        &shared_cos_exact_backlogs,
        &shared_cos_queue_leases,
        &shared_cos_queue_vtime_floors,
        &shared_mirror_targets,
        poll_mode,
        &cos_status,
        &runtime_atomics,
        &cold_path_atomics,
    );
    // #5143: STARTUP READINESS report. The in-thread XSK/UMEM binds are now
    // done — `bindings` holds ONLY the planned bindings that actually bound
    // (setup's Err arm records a bind failure by leaving the failed binding
    // out of this vec). Report the achieved bound-slot set to the
    // `bring_up_workers` readiness barrier BEFORE entering the steady loop, so
    // a worker that came up with an EMPTY/PARTIAL binding set can no longer
    // masquerade as ready on the strength of a live heartbeat alone (the #5143
    // silent forwarding outage). Send-failure is harmless: it means the
    // barrier already gave up on this generation (deadline elapsed) and
    // dropped the receiver — the worker is about to be stopped/joined anyway.
    {
        let bound_slots: Vec<u32> = bindings.iter().map(|binding| binding.slot).collect();
        // #6245: carry the EXPLICIT per-slot terminal failures + recovered
        // shared-group fallbacks (both empty on the all-bound success path) so
        // the readiness barrier's fail-closed diagnostic names the cause,
        // rather than inferring it from the missing slots alone.
        let _ = startup_report_tx.send(WorkerStartupReport {
            worker_id,
            bound_slots,
            binding_failures,
            recovered_fallbacks,
        });
    }
    let ipsec_inner_transport = slow_path
        .as_ref()
        .map(|slow_path| slow_path.ipsec_inner_transport());
    let mut wg_uncovered_batch =
        crate::afxdp::wg_uncovered_forward::WgUncoveredInjectedBatch::new();
    const COS_STATUS_INTERVAL_NS: u64 = 100_000_000;
    let mut ipsec_inner_batch = IpsecInnerDoubleBatch::new();
    let mut ipsec_inner_queue_scratch =
        Vec::<IpsecInnerVerdict>::with_capacity(IPSEC_INNER_DRAIN_BUDGET);
    let mut ipsec_inner_completions =
        Vec::<IpsecInnerVerdict>::with_capacity(IPSEC_INNER_DRAIN_BUDGET);
    let mut idle_iters = 0u32;
    // #6431: one-shot latch for the degraded-idle-poll log. The condition that
    // sets it (a hard errno, or a fault-only revents set) repeats every pass,
    // so an unlatched log would itself become the flood the backoff exists to
    // prevent.
    let mut idle_poll_degraded = false;
    let mut poll_start = 0usize;
    // #7201: the recycled landing buffer for `apply_worker_commands`'s bounded
    // prefix drain. Owned here, outside the loop, because the point is that it
    // is REUSED: the drain it replaces did `core::mem::take(&mut *pending)`,
    // which handed the worker the producers' allocation and left the SHARED
    // deque at zero capacity for the producers to regrow under the lock on every
    // pass. Sized to the budget once; entered and left empty each call, so it
    // settles at that capacity and never reallocates.
    let mut command_scratch: VecDeque<WorkerCommand> =
        VecDeque::with_capacity(crate::afxdp::worker_queue::WORKER_COMMAND_DRAIN_BUDGET);
    let mut shared_recycles = Vec::with_capacity((RX_BATCH_SIZE as usize).saturating_mul(2));
    // #5468: per-drain-cycle aggregate lossless-wedge latch. `flush_session_deltas`
    // bounds each individual lossless send to `WORKER_LOSSLESS_QUEUE_BUDGET`, but
    // the #2442 loss-of-sync resync and the #2653 command export call it ONCE PER
    // 256-delta batch across the whole owned-session set — so an unread peer would
    // otherwise cost ~(K/256) budgets of worker-loop stall for K owned sessions,
    // re-crossing HEARTBEAT_STALE_AFTER for large K and re-triggering the SAME
    // spurious failover via the resync path. Seeded false at the top of every loop
    // iteration below and threaded through EVERY `flush_session_deltas` call this
    // cycle: the first wedge sets it, and later batches inherit it and skip the
    // lossless wait (still draining to the live buffers / shared tables / peer
    // delete replication), so the aggregate worker-loop lossless wait stays ~1
    // budget regardless of K. The loss-of-sync latch still fires on every wedged
    // batch, so the resync retries next cycle (deliver-or-resync, never a drop).
    // Declared uninitialized: the loop-top reset below is the first write every
    // iteration, so a healthy consumer never inherits a stale wedge.
    let mut worker_lossless_wedged: bool;
    // #2669: flush a freshly-drained delta batch to its consumers. Used at
    // all three drain sites (resync macro, exported-sequences branch, else
    // branch). The drain that produced `$deltas` already popped them off the
    // ring PERMANENTLY, so this flush MUST run regardless of whether a binding
    // exists — otherwise the deltas are silently discarded and HA peers,
    // sibling workers, the shared conntrack/session tables, and CLI/gRPC
    // visibility diverge (the original bug). When a binding exists we use its
    // identity + live RPC queue + per-binding session-map fd, exactly as
    // before. When `bindings` is empty we synthesize a binding identity
    // (labels only — no XSK), pass `None` for the per-binding RPC queue, and
    // fall back to the loop-cached map fds (which are `-1`, making the live
    // session-map delete a harmless EBADF no-op — that map belongs to the
    // absent binding; the shared tables, HA replication, and event stream are
    // the consumers that actually matter here).
    // Debug: periodic summary counters
    // #8586: the delete-drop epoch this worker has already reconciled against.
    // Seeded from the CURRENT value rather than 0 so a worker that starts after
    // some other worker's refusals does not run one spurious sweep on its first
    // pass.
    let mut last_delete_drop_epoch =
        crate::afxdp::session_glue::session_delete_drop_epoch(worker_id);
    // #9327: the delete-drop sweep is resumable and budgeted. Declared beside
    // the epoch it is armed by, and carried across passes so no single pass
    // exceeds the RX-ring fill time.
    let mut delete_drop_sweep = crate::afxdp::session_glue::DeleteDropSweep::default();
    // #9752: the installing-table purge walk is resumable and budgeted, like
    // the sweep above. Armed by re-resolve terminal observations.
    let mut install_table_purge = crate::afxdp::session_glue::InstallTablePurge::default();
    // #9720: the transition-debt epoch this worker has already applied
    // against, plus the carried pending flag. Seeded from CURRENT (same
    // no-spurious-first-pass argument as the delete-drop epoch above);
    // `register` clears the slot but not the epoch, so a reused worker id
    // starts quiet and any record after the seed bumps past it.
    let mut last_transition_debt_epoch =
        crate::afxdp::worker_queue::transition_debt_epoch(worker_id);
    let mut transition_debt_pending = false;
    let mut last_session_import_repair_epoch =
        crate::afxdp::worker_queue::session_import_repair_epoch(worker_id);
    let mut session_import_repair_pending = false;
    // #9856: resumable owner-RG CommandExport (multi-pass cursor). `None` =
    // idle. Adopted from the tick's dispatch results when Export commands
    // arrive; cleared on completion (after acking). Paced like the sweeps
    // above: one budgeted slice per pass, RX/TX/heartbeat between slices.
    const EXPORT_SLICE_BUDGET: usize = 1024; // max slab slots scanned per slice
    const EXPORT_SLICE_EMITS: usize = 256; // max sessions converted per slice
    const EXPORT_SLICE_DEADLINE_NS: u64 = 500_000; // 500us slice cap
    let mut worker_export: Option<WorkerExportState> = None;
    // #9856: echo-batch scratch, reused across slices. The walk borrows
    // `sessions` shared, so the echo emits — which need `&mut` — run after
    // the walk from this buffer, then drain.
    let mut export_echo_scratch: Vec<(
        crate::session::SessionKey,
        crate::session::SessionDecision,
        crate::session::SessionMetadata,
        crate::session::SessionOrigin,
    )> = Vec::with_capacity(EXPORT_SLICE_EMITS);
    let mut dbg_last_report_ns = monotonic_nanos();
    // #1776: the per-interval cfg(debug-log) dbg_* counters are
    // consolidated into debug_report::DbgCounters (single-line
    // default() reset each report tick). dbg_last_report_ns above and
    // the stall baselines below are PERSISTENT debug state that
    // survives across report intervals — deliberately NOT DbgCounters
    // fields, so the interval reset cannot wipe them (plan v3.1 AGY
    // CORRECTNESS-1).
    #[cfg(feature = "debug-log")]
    let mut dbg = debug_report::DbgCounters::default();
    #[cfg(feature = "debug-log")]
    let mut stall_prev_fwd = 0u64;
    #[cfg(feature = "debug-log")]
    let mut stall_reported = false;
    const DBG_REPORT_INTERVAL_NS: u64 = 1_000_000_000; // 1 second
    // BPF conntrack last_seen refresh (#333, made incremental in #5287).
    // Keeps `show security flow session` idle times / volume accurate without
    // per-second syscall overhead per session.
    //
    // #5287: the refresh is now a budgeted, resumable slice instead of one
    // full-table pass. Near the 131072-entry cap the old single pass did a BPF
    // lookup + update per forward entry (tens of thousands of synchronous
    // kernel crossings) between two RX/TX polls — a deterministic per-interval
    // latency spike on this low-latency core. Now each slice refreshes at most
    // CT_REFRESH_SLICE_BUDGET slab slots from a persistent cursor
    // (`ct_refresh_cursor`) and resumes on the next slice, at CT_SLICE_INTERVAL_NS
    // cadence, with RX/TX/heartbeat interleaved between slices. Successive
    // full-table CYCLES are paced to CT_REFRESH_WINDOW_NS so a small or idle
    // table is not over-refreshed (steady-state syscall rate is unchanged from
    // the old 10s full-table cadence). Freshness/latency tradeoff: at the
    // 131072 default cap and 100ms cadence a full cycle spans ~64 slices
    // (~6.4s <= the 10s window); if `max_sessions` is raised far above the
    // default a cycle stretches past the window (freshness degrades gracefully),
    // but the per-slice cost stays hard-bounded at CT_REFRESH_SLICE_BUDGET — no
    // single tick ever stalls the core again.
    const CT_REFRESH_WINDOW_NS: u64 = 10_000_000_000; // full-table freshness target
    const CT_SLICE_INTERVAL_NS: u64 = 100_000_000; // 100ms between slices
    const CT_REFRESH_SLICE_BUDGET: usize = 2048; // max slab slots per slice
    let mut last_ct_slice_ns: u64 = 0;
    let mut ct_cycle_start_ns: u64 = 0;
    // Persistent slab-index cursor: 0 means "between cycles / at the top".
    let mut ct_refresh_cursor: usize = 0;
    // #869: worker-runtime telemetry.  Local counters, published to
    // `runtime_atomics` on the ~1s cadence below.
    use crate::afxdp::worker_runtime::{
        WorkerRuntimeCounters, WorkerRuntimeState, sample_thread_cpu_ns,
    };
    let mut wr_counters = WorkerRuntimeCounters::default();
    let mut wr_state = WorkerRuntimeState::IdleBlock;
    let mut wr_last_loop_ns = monotonic_nanos();
    let mut wr_last_publish_ns = wr_last_loop_ns;
    // #11075: last route-change alarm emission (rate-limit state).
    let mut last_route_change_alarm_ns: u64 = 0;
    // #1760 W1: previous-snapshot values for the durable journald
    // collision warn. Compared on the ~1s publish cadence below — zero
    // per-packet work, one u64 compare per publish while the counters
    // stay 0. The shared-displacement value is process-global, so every
    // worker tracks its own prev and the process-global CAS throttle in
    // shared_ops bounds emission to <=1 line/min regardless of how many
    // workers observe the same increment.
    let mut wr_prev_nat_collisions: u64 = 0;
    let mut wr_prev_shared_displacements: u64 = 0;
    const WR_PUBLISH_INTERVAL_NS: u64 = 1_000_000_000;
    // Expiry closes that could not obtain the tuple gate remain outside the
    // session delta ring. This preserves the all-close guarantee for overflow
    // entries without competing with the ring's bounded capacity.
    let mut deferred_expiry_overflow_deltas: Vec<SessionDelta> = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let loop_now_ns = monotonic_nanos();
        // #5468: reset the per-drain-cycle aggregate lossless-wedge latch. It is
        // threaded through every `flush_session_deltas` call this iteration (the
        // steady-state drain, the #2442 resync, and the #2653 export) so the
        // FIRST wedge caps the whole cycle's lossless wait at ~1 budget; a fresh
        // iteration must start un-wedged so a healthy consumer pays no penalty.
        // #9856: the CommandExport slice keeps this per-pass reset — its
        // control leg never touches the lossless queue (Full pauses the
        // cursor instead of wedging) and its echo deltas are
        // bulk_resync-marked (non-arming), so no cross-pass extension.
        worker_lossless_wedged = false;
        // #869: attribute elapsed delta to the previous loop's state.
        {
            let delta = loop_now_ns.saturating_sub(wr_last_loop_ns);
            wr_counters.wall_ns = wr_counters.wall_ns.wrapping_add(delta);
            match wr_state {
                WorkerRuntimeState::Active => {
                    wr_counters.active_ns = wr_counters.active_ns.wrapping_add(delta);
                }
                WorkerRuntimeState::IdleSpin => {
                    wr_counters.idle_spin_ns = wr_counters.idle_spin_ns.wrapping_add(delta);
                }
                WorkerRuntimeState::IdleBlock => {
                    wr_counters.idle_block_ns = wr_counters.idle_block_ns.wrapping_add(delta);
                }
            }
            wr_last_loop_ns = loop_now_ns;
            if loop_now_ns.saturating_sub(wr_last_publish_ns) >= WR_PUBLISH_INTERVAL_NS {
                // Skip on transient clock_gettime failure (sample == 0):
                // overwriting a previously-published nonzero value with 0
                // would make the Prometheus counter go backwards and
                // break `rate()` queries.
                let sampled_cpu_ns = sample_thread_cpu_ns();
                if sampled_cpu_ns != 0 {
                    wr_counters.thread_cpu_ns = sampled_cpu_ns;
                }
                refresh_worker_cos_queue_lease_runtime_counters(&mut wr_counters, &bindings);
                // #4800: per-worker transit new-flow install count.
                //
                // REACHABILITY-BOUND SINCE #6971, structurally. Nothing drives
                // `worker_loop` in any test, so deleting THIS LINE used to leave
                // the whole suite green while the wire field pinned at 0 and both
                // #4800 cross-worker analyzer gates (`active_workers < 3`,
                // `max_worker_share > 0.60`) silently stopped discriminating. The
                // `refresh_worker_cos_queue_lease_*` call above it had the same
                // gap. Both are now pinned by
                // `worker_loop_refreshes_publish_tick_counters_6971`
                // (server/tests.rs), which also asserts they sit INSIDE this
                // publish-tick block rather than merely existing — a source pin,
                // because `worker_loop` takes five heavyweight parameters and is
                // spawned only from coordinator bringup against real AF_XDP
                // sockets, so no test can drive it and inventing a seam would
                // just move the unbound boundary up one level.
                refresh_worker_new_flow_install_counters(&mut wr_counters, &bindings);
                wr_counters.session_table_entries = sessions.len() as u64;
                wr_counters.max_sessions = sessions.max_sessions() as u64;
                wr_counters.nat_reverse_key_collisions = sessions.nat_reverse_key_collisions();
                wr_counters.nat_reverse_key_collisions_distinct_src =
                    sessions.nat_reverse_key_collisions_distinct_src();
                // #1861: install-refusal trio from the worker's
                // SessionTable (create_drops was write-only before).
                wr_counters.session_create_drops = sessions.create_drops();
                let pptp = sessions.pptp().counters();
                wr_counters.pptp_unassociated_packets = pptp.unassociated;
                wr_counters.pptp_expired_idle = pptp.expired_idle;
                wr_counters.pptp_handle_collisions = pptp.handle_collisions;
                wr_counters.pptp_allocator_collisions = pptp.allocator_collisions;
                // #7919: (no handle, stale handle, key mismatch)
                let (miss_nh, miss_sh, miss_km) = sessions.lookup_miss_counts();
                wr_counters.session_lookup_miss_no_handle = miss_nh;
                wr_counters.session_lookup_miss_stale_handle = miss_sh;
                wr_counters.session_lookup_miss_key_mismatch = miss_km;
                wr_counters.session_install_admission_refused = sessions.admission_refused();
                wr_counters.session_install_partial = sessions.install_partial();
                let gc = sessions.cumulative_pop_stats();
                wr_counters.session_gc_scanned = gc.scanned as u64;
                wr_counters.session_gc_dropped_gone = gc.dropped_gone as u64;
                wr_counters.session_gc_dropped_stale = gc.dropped_stale as u64;
                wr_counters.session_gc_re_bucketed = gc.re_bucketed as u64;
                wr_counters.session_gc_held_standby = gc.held_standby as u64;
                wr_counters.session_gc_reaped_stale_synced = gc.reaped_stale_synced as u64;
                wr_counters.session_gc_healed_on_promote = gc.healed_on_promote as u64;
                wr_counters.session_gc_aged_owner_rg_zero_active_node =
                    gc.aged_owner_rg_zero_active_node as u64;
                wr_counters.session_gc_kept_alive_by_companion = gc.kept_alive_by_companion as u64;
                // #1760 W1: durable artifact for the reverse-key-collision
                // watch. The in-process counters reset on every restart
                // and the lab has no long-term Prometheus store, so a
                // collision that happened before a redeploy would be
                // unobservable without a journald line. Rate-limited by
                // the process-global 60s CAS throttle; honest-semantics
                // text per docs/research/1760-reverse-key-v2/plan.md §2.3.
                let shared_displacements =
                    crate::afxdp::shared_ops::NAT_REVERSE_KEY_SHARED_DISPLACEMENTS
                        .load(Ordering::Relaxed);
                if wr_counters.nat_reverse_key_collisions > wr_prev_nat_collisions
                    || shared_displacements > wr_prev_shared_displacements
                {
                    // Only consume the pending increment when the warn was
                    // actually emitted: a throttled increment keeps the
                    // prevs unchanged and retries on later publish ticks,
                    // so a burst inside one 60s window (or during the
                    // first window after start, when the CAS slot is
                    // still warming) still produces its journald line
                    // instead of being silently swallowed.
                    if crate::afxdp::shared_ops::try_claim_nat_reverse_key_warn(loop_now_ns) {
                        eprintln!(
                            "xpf-dp: NAT reverse-key collision detected (worker={} \
                             local_total={} shared_total={}) — #1760 latent 1:N \
                             reverse-path corruption; counts are displacement \
                             events (>=1 means a real collision occurred; not a \
                             pair census — standing collisions against an \
                             already-unindexed session are not counted)",
                            worker_id, wr_counters.nat_reverse_key_collisions, shared_displacements,
                        );
                        wr_prev_nat_collisions = wr_counters.nat_reverse_key_collisions;
                        wr_prev_shared_displacements = shared_displacements;
                    }
                }
                runtime_atomics.publish(&wr_counters, loop_now_ns);
                // #1621: alongside the runtime publish, merge each
                // binding's cold-path worker-local counters into a
                // single WorkerColdPathCounters and publish via the
                // sibling atomics' own cold_window_gen seqlock.
                //
                // Per plan v1 §4.2: saturating_add buckets / sum_ns /
                // samples / sample_phase / wrapper_underflow_count;
                // OR alias_seen; first-non-zero first_key (cross-
                // binding aliasing detected when bindings disagree).
                {
                    use crate::afxdp::cold_path_hist as cph;
                    let mut merged = cph::WorkerColdPathCounters::default();
                    for binding in bindings.iter() {
                        let src = &binding.cold_path;
                        merged.sample_phase = merged.sample_phase.saturating_add(src.sample_phase);
                        merged.wrapper_underflow_count = merged
                            .wrapper_underflow_count
                            .saturating_add(src.wrapper_underflow_count);
                        for slot in 0..cph::POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                            merged.sum_ns[slot] =
                                merged.sum_ns[slot].saturating_add(src.sum_ns[slot]);
                            merged.samples[slot] =
                                merged.samples[slot].saturating_add(src.samples[slot]);
                            for b in 0..cph::POLICY_COLD_PATH_HIST_BUCKETS {
                                merged.buckets[slot][b] =
                                    merged.buckets[slot][b].saturating_add(src.buckets[slot][b]);
                            }
                            // first_key + builder_collision cross-binding merge.
                            if merged.first_key[slot] == 0 {
                                merged.first_key[slot] = src.first_key[slot];
                            } else if src.first_key[slot] != 0
                                && src.first_key[slot] != merged.first_key[slot]
                            {
                                merged.builder_collision[slot] = true;
                            }
                            merged.builder_collision[slot] |= src.builder_collision[slot];
                        }
                    }
                    // All bindings on this worker share the same pinned
                    // core ⇒ same TSC calibration. Take any binding's
                    // value (default = 0 if no bindings — calibration
                    // not yet installed).
                    if let Some(first) = bindings.first() {
                        merged.ns_per_tsc_q32 = first.cold_path.ns_per_tsc_q32;
                        merged.wrapper_ns_baseline = first.cold_path.wrapper_ns_baseline;
                        merged.clock_source = first.cold_path.clock_source;
                    }
                    cold_path_atomics.publish_from_local(&merged);
                }
                wr_last_publish_ns = loop_now_ns;
            }
        }
        let loop_now_secs = loop_now_ns / 1_000_000_000;
        let mut rebuild_cos_fast_interfaces = false;
        // #6592: ONE load for both halves. The coordinator publishes
        // validation and forwarding in a single `RuntimeView`, so whichever
        // view this observes gives a coherent pair — neither torn orientation
        // is reachable. Still read BEFORE the CoS map Arcs below (#5166), and
        // still #1188-short-circuited on the forwarding Arc — see
        // `refresh_runtime_view`.
        let (new_forwarding_opt, live_validation) =
            refresh_runtime_view(&forwarding, &shared_runtime, |view| {
                let Some(transport) = ipsec_inner_transport.as_ref() else {
                    return;
                };
                let taken = transport.drain_worker(worker_id, &mut ipsec_inner_batch);
                if taken != 0 {
                    for descriptor in ipsec_inner_batch.current().iter().take(taken) {
                        let descriptor_now_ns = monotonic_nanos();
                        let decision = run_before_pmech_deadline(
                            descriptor.deadline_mono_ns,
                            descriptor_now_ns,
                            || {
                                let verdict = IpsecInnerVerdict::Deny {
                                    request_id: descriptor.request_id,
                                    connection_id: descriptor.connection_id,
                                    stage: "d11_deadline_expired",
                                    reason: ipsec_reason::SUBMIT_UNAVAILABLE,
                                    policy_id: 0,
                                };
                                if let Err(failed) =
                                    transport.post_worker_verdict(worker_id, verdict)
                                {
                                    let _ = transport.requeue_worker_verdict(worker_id, failed);
                                }
                            },
                            || {
                                let stn_len =
                                    usize::from(descriptor.stn_len).min(descriptor.stn.len());
                                let stn =
                                    std::str::from_utf8(&descriptor.stn[..stn_len]).unwrap_or("");
                                let input = IpsecInnerInput {
                                    slab_id: descriptor.slab_id,
                                    inner_packet: &[],
                                    stn,
                                    inner_family: descriptor.inner_family,
                                    inner_eth_proto: descriptor.inner_eth_proto,
                                    protocol: descriptor.protocol,
                                    rel_l4_offset: descriptor.rel_l4_offset,
                                    payload_offset: descriptor.payload_offset,
                                    // The Go owned_ifindex claim is untrusted; D14 compares
                                    // it against the authoritative tunnel-row identity.
                                    logical_ifindex: i32::try_from(descriptor.stn_ifindex)
                                        .unwrap_or(0),
                                    rx_queue_index: descriptor.rx_queue_index,
                                    advisory: IpsecInnerAdvisory {
                                        snapshot_generation: descriptor.snapshot_generation,
                                        config_generation: descriptor.config_generation,
                                        fib_generation: descriptor.fib_generation,
                                        zone_id: descriptor.advisory_zone_id,
                                        if_id: descriptor.advisory_if_id,
                                        pmech_inventory_generation: descriptor
                                            .pmech_inventory_generation,
                                        pmech_inventory_fib_generation: descriptor
                                            .pmech_inventory_fib_generation,
                                        pmech_policy_identity: descriptor.pmech_policy_identity,
                                        expected_routing_domain: descriptor.expected_routing_domain,
                                        expected_fib_table: descriptor.expected_fib_table,
                                    },
                                    descriptor: Some(descriptor),
                                };
                                adjudicate_descriptor(
                                    view,
                                    transport.pool().as_ref(),
                                    descriptor,
                                    input,
                                )
                            },
                        );
                        let Some(decision) = decision else {
                            continue;
                        };
                        // #9506 S9.5 FORWARD permit join: a successful
                        // adjudication of a SUBMIT_FLAG_FORWARD frame arms the
                        // leased adjudicated-TUN write while this worker still
                        // owns the slab. Arming (or its refusal rollback)
                        // happens BEFORE the verdict is posted, so the verdict
                        // drain can never terminalize an armed entry; the
                        // writer thread's pre-write check linearizes
                        // authorization and resolve_write emits the terminal.
                        // Frames without the flag (the D11 witness path) keep
                        // the deny-only WouldPermit terminal.
                        if decision.is_would_permit() && descriptor.flags & SUBMIT_FLAG_FORWARD != 0
                        {
                            if let Some(slow_path) = slow_path.as_ref() {
                                let lease = ReinjectLease {
                                    request_id: descriptor.request_id,
                                    permit_epoch: descriptor.permit_epoch,
                                    queue_number: descriptor.queue_number,
                                    queue_epoch: descriptor.queue_epoch,
                                };
                                let forwarded = match transport.pool().buffer(descriptor.slab_id) {
                                    Some(buffer) => match buffer.get(..descriptor.len as usize) {
                                        Some(bytes) => slow_path.forward_ipsec_inner_permit(
                                            bytes.to_vec(),
                                            lease,
                                            descriptor.flow_tag,
                                            descriptor.connection_id,
                                        ),
                                        None => false,
                                    },
                                    None => false,
                                };
                                if !forwarded {
                                    // The completion entry is already a
                                    // definitive Refused terminal (or was
                                    // never armed); fail-closed, no write.
                                }
                            }
                        }
                        let verdict = verdict_from_decision(&decision);
                        if let Err(failed) = transport.post_worker_verdict(worker_id, verdict) {
                            let _ = transport.requeue_worker_verdict(worker_id, failed);
                        }
                    }
                }
                ipsec_inner_completions.clear();
                transport.drain_verdicts_into(
                    &mut ipsec_inner_queue_scratch,
                    &mut ipsec_inner_completions,
                    IPSEC_INNER_DRAIN_BUDGET,
                );
                if let Some(slow_path) = slow_path.as_ref() {
                    for verdict in ipsec_inner_completions.drain(..) {
                        let _ = slow_path.complete_ipsec_inner_verdict(verdict);
                    }
                } else {
                    ipsec_inner_completions.clear();
                }
            });
        // #11075/#12074: FIB generation advanced. #11373 re-resolves stale
        // sessions on their next hit; #12074 re-judges zone policy if that
        // resolution changes the egress zone. Count sessions awaiting that
        // lazy work and rate-limit the alarm; this tick does no route lookup.
        if crate::afxdp::poll_descriptor::should_alarm_route_change(
            validation.fib_generation,
            live_validation.fib_generation,
            sessions.len(),
            last_route_change_alarm_ns,
            loop_now_ns,
        ) {
            crate::afxdp::poll_descriptor::ROUTE_CHANGE_UNREJUDGED_SESSIONS_TOTAL
                .fetch_add(sessions.len() as u64, std::sync::atomic::Ordering::Relaxed);
            eprintln!(
                "xpf-userspace-dp: WARNING: FIB generation {} -> {} with {} established sessions: stale sessions re-resolve on next hit; zone policy is re-judged if the egress zone changes (#11373/#12074)",
                validation.fib_generation,
                live_validation.fib_generation,
                sessions.len(),
            );
            last_route_change_alarm_ns = loop_now_ns;
        }
        if live_validation != validation {
            validation = live_validation;
        }
        if let Some(new_forwarding) = new_forwarding_opt {
            // Compare BEFORE assignment — needs both old and new.
            let cos_changed =
                cos_runtime_config_changed(forwarding.as_ref(), new_forwarding.as_ref());
            let (dscp_changed_v4, dscp_changed_v6) =
                crate::filter::input_dscp_filter_families_changed(
                    &forwarding.filter_state,
                    &new_forwarding.filter_state,
                );
            // #11330: lo0 republish scans the full session table. Compare
            // semantic filter content before assignment so unchanged rotations
            // can skip that walk; positional filter ids are not semantics.
            let (lo0_filter_changed_v4, lo0_filter_changed_v6) =
                crate::filter::lo0_filter_families_changed(
                    &forwarding.filter_state,
                    &new_forwarding.filter_state,
                );
            let lo0_filter_changed = lo0_filter_changed_v4 || lo0_filter_changed_v6;
            // #2362: a per-packet-L4 (tcp-flags / is-fragment / icmp-type /
            // icmp-code) input filter rotation has the same revalidation
            // requirement as a DSCP filter rotation — established sessions whose
            // first packet was admitted under the old term set must be purged so
            // the new term is re-evaluated. Fold the two change-sets into one
            // purge per family.
            let (per_packet_changed_v4, per_packet_changed_v6) =
                crate::filter::input_per_packet_l4_filter_families_changed(
                    &forwarding.filter_state,
                    &new_forwarding.filter_state,
                );
            let purge_input_dscp_v4 = dscp_changed_v4 || per_packet_changed_v4;
            let purge_input_dscp_v6 = dscp_changed_v6 || per_packet_changed_v6;
            // #9526: compare BEFORE assignment. The Go commit sweep cannot clear
            // the literal first policy's sessions (policy_id 0 is overloaded on
            // the wire), so when this rotation removes the old snapshot's
            // policy_id-0 rule, the sessions bound to it are purged below.
            // Worker-local old vs new, like the cold-path slot compare: a worker
            // that skipped intermediate generations still sees the rule vanish.
            let deleted_first_policy =
                deleted_first_policy_rule_id(&forwarding.policy, &new_forwarding.policy);
            // #10510: derive actual old-minus-new zone disappearance before
            // assigning the new snapshot. Empty producer maps are a safe no-op.
            let removed_zone_ids = removed_zone_ids_for_rotation(&forwarding, &new_forwarding);
            let extensive_rematch = new_forwarding.policy_rematch_extensive;

            // Use NEW values for dependent state updates (forwarding-site
            // ordering — old `forwarding` is stale once rotated).
            screen_state.update_profiles(new_forwarding.screen_profiles.clone());
            // #3082: re-thread the references-missing-profile set on every
            // runtime forwarding-snapshot rotation so a newly-introduced
            // dangling screen reference starts WARNing (and a fixed one stops).
            screen_state.update_missing_profiles(new_forwarding.screen_missing_profiles.clone());
            screen_state.update_inert_profiles(new_forwarding.screen_inert_profiles.clone());
            screen_state.update_syn_cookie_keys(
                new_forwarding.syn_cookie_master_key.0,
                new_forwarding.syn_cookie_key_ring.clone(),
            );
            sessions.set_timeouts(new_forwarding.session_timeouts);
            // #3527: re-apply the per-screened-zone half-open overrides on every
            // runtime forwarding-snapshot rotation. `set_opening_overrides` is a
            // full replace, so a zone whose `syn-flood timeout` was removed
            // drops out and reverts to the global default on the next install.
            sessions.set_opening_overrides(new_forwarding.session_opening_overrides.clone());
            // #2134/#11057: re-derive optional destination accounting on every
            // runtime forwarding-snapshot rotation. An ON->OFF transition
            // clears only the destination map; source counts remain current
            // for the always-enforced default per-source quota.
            sessions.set_session_limit_active(screen_state.any_session_limit_dst_configured());

            // #1635 (plan §2.4): a config apply may have reassigned
            // cold-path histogram slots to new zone-pairs. Zero those
            // slots in every binding's worker-local accumulator BEFORE
            // any record_sample into the reused slot, so a reused slot
            // never carries the previous zone-pair's counts.
            //
            // Copilot code-r2: derive the zero-set from THIS WORKER's
            // OWN old map vs the new map, NOT from the coordinator's
            // `slots_to_zero` list. A worker can skip intermediate
            // ForwardingState generations (ArcSwap only ever delivers
            // the latest), and the coordinator computes `slots_to_zero`
            // relative to its immediately-previous map — so a slot
            // reassigned in a skipped generation would be absent from
            // the latest list (it now looks "retained"). Comparing the
            // worker's actual old slot-map inverse against the new one
            // is generation-independent: any slot whose mapping changed
            // since the worker last observed it gets zeroed. The
            // sibling atomics are overwritten at the next publish merge
            // from the freshly-zeroed local accumulator.
            {
                let old_inverse = &forwarding.cold_path_slot_map.inverse;
                let new_inverse = &new_forwarding.cold_path_slot_map.inverse;
                for slot in 0..crate::afxdp::cold_path_hist::POLICY_COLD_PATH_ZONE_PAIR_SLOTS {
                    let new_pair = new_inverse.get(slot).copied().flatten();
                    // Zero when the slot now maps to a pair that differs
                    // from what the worker last saw there. A freed slot
                    // (new == None) keeps its stale local data harmlessly
                    // — it is unmapped, never sampled, and gets zeroed
                    // when next reassigned.
                    if new_pair.is_some() && new_pair != old_inverse.get(slot).copied().flatten() {
                        for binding in bindings.iter_mut() {
                            binding.cold_path.zero_slot(slot);
                        }
                    }
                }
            }

            // Teardown runs against the NEW state deliberately: interface-NAT
            // identity is Arc-shared across the rotation, pool/NAT64
            // allocators are reused-or-reseeded into the new objects
            // (parse_source_nat_rules_with_previous + carry), and old-only
            // allocator objects die with the old ForwardingState — so only
            // the new tables can free the live (possibly carried)
            // reservation. Releasing against the old state would miss carried
            // copies and strand them in the new allocators.
            let (rematched_rebound, rematched_purged) = rematch_bound_first_policy_sessions(
                &forwarding,
                &new_forwarding,
                &mut sessions,
                &session_map,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &peer_worker_commands,
                &worker_commands_by_id,
                worker_id,
                loop_now_ns,
            );
            if rematched_rebound + rematched_purged > 0 {
                debug_log!(
                    "RENAMED_FIRST_POLICY_REMAP: worker={} rebound={} purged={}",
                    worker_id,
                    rematched_rebound,
                    rematched_purged,
                );
            }
            forwarding = new_forwarding;
            let rebound_policy_sessions = rebind_policy_sessions_from_snapshot(
                &mut sessions,
                &forwarding,
                &forwarding.policy_session_rebinds,
                &session_map,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &peer_worker_commands,
                &worker_commands_by_id,
                worker_id,
                loop_now_ns,
            );
            if rebound_policy_sessions > 0 {
                debug_log!(
                    "RENAMED_POLICY_REBIND: worker={} sessions={}",
                    worker_id,
                    rebound_policy_sessions,
                );
            }

            let purged_removed_zone_sessions = purge_sessions_with_removed_zone_ids(
                &mut sessions,
                session_map.handle(),
                conntrack_v4_fd,
                conntrack_v6_fd,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &peer_worker_commands,
                &worker_commands_by_id,
                &forwarding,
                &removed_zone_ids,
                loop_now_ns,
                worker_id,
            );
            if purged_removed_zone_sessions > 0 {
                debug_log!(
                    "REMOVED_ZONE_SYNC_PURGE: worker={} zones={} sessions={}",
                    worker_id,
                    removed_zone_ids.len(),
                    purged_removed_zone_sessions,
                );
            }
            let purged_input_dscp = purge_sessions_for_input_dscp_filter_revalidation(
                &mut sessions,
                session_map.handle(),
                conntrack_v4_fd,
                conntrack_v6_fd,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &peer_worker_commands,
                &worker_commands_by_id,
                &forwarding,
                purge_input_dscp_v4,
                purge_input_dscp_v6,
                loop_now_ns,
                worker_id,
            );
            if purged_input_dscp > 0 {
                debug_log!(
                    "INPUT_DSCP_FILTER_PURGE: worker={} sessions={}",
                    worker_id,
                    purged_input_dscp,
                );
            }
            if !extensive_rematch {
                if let Some(rule_id) = deleted_first_policy.as_deref() {
                    let purged_first_policy = purge_sessions_bound_to_deleted_first_policy(
                        &mut sessions,
                        session_map.handle(),
                        conntrack_v4_fd,
                        conntrack_v6_fd,
                        &shared_sessions,
                        &shared_nat_sessions,
                        &shared_forward_wire_sessions,
                        &shared_owner_rg_indexes,
                        &peer_worker_commands,
                        &worker_commands_by_id,
                        &forwarding,
                        rule_id,
                        loop_now_ns,
                        worker_id,
                    );
                    if purged_first_policy > 0 {
                        debug_log!(
                            "DELETED_FIRST_POLICY_PURGE: worker={} rule={} sessions={}",
                            worker_id,
                            rule_id,
                            purged_first_policy,
                        );
                    }
                }
            }
            let republished = republish_local_delivery_sessions_for_lo0_filter(
                &sessions,
                session_map.handle(),
                &forwarding,
                lo0_filter_changed,
            );
            if republished > 0 {
                debug_log!(
                    "LO0_FILTER_REPUBLISH: worker={} local_delivery_sessions={}",
                    worker_id,
                    republished,
                );
            }

            if cos_changed {
                reset_worker_cos_runtimes(&mut bindings, &mut shared_recycles);
                apply_shared_recycles_to_bindings(
                    &mut bindings,
                    &binding_lookup,
                    &mut shared_recycles,
                );
                rebuild_cos_fast_interfaces = true;
            }
        }
        if let Some(new_x) = load_arc_if_changed(&mirror_targets, &shared_mirror_targets) {
            mirror_targets = new_x;
        }
        if let Some(new_x) = load_arc_if_changed(
            &cos_owner_worker_by_queue,
            &shared_cos_owner_worker_by_queue,
        ) {
            cos_owner_worker_by_queue = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_owner_live_by_queue, &shared_cos_owner_live_by_queue)
        {
            cos_owner_live_by_queue = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) = load_arc_if_changed(&cos_shared_root_leases, &shared_cos_root_leases) {
            for binding in bindings.iter_mut() {
                release_all_cos_root_leases(binding);
                release_all_cos_queue_leases(binding);
            }
            cos_shared_root_leases = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) =
            load_arc_if_changed(&cos_shared_exact_backlogs, &shared_cos_exact_backlogs)
        {
            cos_shared_exact_backlogs = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) = load_arc_if_changed(&cos_shared_queue_leases, &shared_cos_queue_leases)
        {
            for binding in bindings.iter_mut() {
                release_all_cos_queue_leases(binding);
            }
            cos_shared_queue_leases = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if let Some(new_x) = load_arc_if_changed(
            &cos_shared_queue_vtime_floors,
            &shared_cos_queue_vtime_floors,
        ) {
            // #917: Arc-replacement of the V_min floors map.
            // Each shared_exact queue's per-worker slots default
            // to NOT_PARTICIPATING in the new Arc. Workers will
            // re-publish their committed vtime on the next
            // commit-boundary publish; until then peers reading
            // this slot see "not participating" and skip it in
            // V_min reduction (per plan §3.4 / §3.7 lifecycle
            // rules).
            cos_shared_queue_vtime_floors = new_x;
            rebuild_cos_fast_interfaces = true;
        }
        if rebuild_cos_fast_interfaces {
            let cos_owner_live_by_tx_ifindex = build_worker_cos_owner_live_by_tx_ifindex(
                bindings
                    .iter()
                    .map(|binding| (binding.ifindex, binding.live.clone())),
            );
            let cos_fast_interfaces = build_worker_cos_fast_interfaces(
                forwarding.as_ref(),
                worker_id,
                &cos_owner_live_by_tx_ifindex,
                cos_owner_worker_by_queue.as_ref(),
                cos_owner_live_by_queue.as_ref(),
                cos_shared_root_leases.as_ref(),
                cos_shared_exact_backlogs.as_ref(),
                cos_shared_queue_leases.as_ref(),
                cos_shared_queue_vtime_floors.as_ref(),
            );
            for binding in bindings.iter_mut() {
                binding.cos.cos_fast_interfaces = cos_fast_interfaces.clone();
                // #13073: the swap can carry new root leases (worker
                // join/leave); fold them into the materialized runtimes so
                // shared_exact admission keeps partitioning by the live
                // shard count, not a materialization-time snapshot.
                refresh_cos_runtime_shared_root_leases(binding);
            }
            // The new SharedCoSExactBacklog slots in the freshly built
            // cos_fast_interfaces start at zero. Republish the current
            // exact-queue backlog for every binding/ifindex so peer workers
            // do not observe a false-zero window until the next organic
            // enqueue or drain refresh.
            for binding in bindings.iter() {
                for &root_ifindex in binding.cos.cos_interfaces.keys() {
                    publish_cos_exact_backlog(binding, root_ifindex);
                }
            }
        }
        let ha_runtime = ha_state.load();
        // Only apply commands when pending — avoids lock overhead on
        // every loop iteration in the common (empty-queue) case.
        // #1807: a poisoned mutex is recovered (and the poison cleared)
        // instead of reading as "no commands" — that turned one worker
        // panic into permanent deafness to coordinator commands.
        let has_commands = crate::afxdp::worker_queue::try_lock_recover(&commands)
            .map(|q| !q.is_empty())
            .unwrap_or(false);
        // #9720/#11360: sample both positional-debt epochs EVERY pass. A
        // record that lands after a queue drain still schedules the out-of-band
        // repair even when no later command arrives.
        let transition_debt_epoch = crate::afxdp::worker_queue::transition_debt_epoch(worker_id);
        let debt_epoch_changed = transition_debt_epoch != last_transition_debt_epoch;
        let session_import_repair_epoch =
            crate::afxdp::worker_queue::session_import_repair_epoch(worker_id);
        let import_repair_epoch_changed =
            session_import_repair_epoch != last_session_import_repair_epoch;
        let should_apply = crate::afxdp::worker_queue::should_apply_worker_commands(
            has_commands,
            debt_epoch_changed,
            transition_debt_pending,
            import_repair_epoch_changed,
            session_import_repair_pending,
        );
        let command_results = if should_apply {
            apply_worker_commands(
                &commands,
                &mut sessions,
                session_map.handle(),
                conntrack_v4_fd,
                conntrack_v6_fd,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
                worker_id,
                &mut command_scratch,
            )
        } else {
            WorkerCommandResults::empty()
        };
        if should_apply {
            last_transition_debt_epoch = transition_debt_epoch;
            last_session_import_repair_epoch = session_import_repair_epoch;
        }
        let WorkerCommandResults {
            cancelled_keys,
            mut deleted_synced_keys,
            mut stale_replay_dropped_keys,
            session_import_repairs,
            exported_sequences,
            session_counter_answers,
            export_owner_rgs,
            export_kick_epoch,
            shaped_tx_requests,
            vacate_all_shared_exact_slots,
            commands_backlogged,
            transition_debt_pending: transition_debt_pending_now,
            session_import_repair_pending: session_import_repair_pending_now,
        } = command_results;
        transition_debt_pending = transition_debt_pending_now;
        session_import_repair_pending = session_import_repair_pending_now;
        if !session_import_repairs.is_empty() {
            crate::afxdp::session_glue::apply_session_import_repairs(
                &session_import_repairs,
                &shared_sessions,
                &mut sessions,
                session_map.handle(),
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
                &mut stale_replay_dropped_keys,
                &mut deleted_synced_keys,
                worker_id,
            );
            session_import_repair_pending =
                crate::afxdp::worker_queue::has_session_import_repair_debt(worker_id);
        }
        // #941 Work item C: HA-demotion vacate. The
        // VacateAllSharedExactSlots WorkerCommand cannot be processed
        // inside `apply_worker_commands` (no BindingWorker access);
        // it sets this flag and the dispatch happens here, where we
        // hold `&mut bindings`. Single-writer invariant: only this
        // worker writes its own slots.
        if vacate_all_shared_exact_slots {
            for binding in bindings.iter_mut() {
                vacate_all_shared_exact_slots_for_binding(binding);
            }
        }
        // #6457: same-thread flow-cache invalidation for every session a
        // control-plane `DeleteSynced` dropped this tick (operator
        // `clear security flow session`, cluster-stale sweep, HA
        // DeleteSynced propagation). `apply_worker_commands` has no
        // `BindingWorker` access, so — exactly like the vacate dispatch
        // above — it records the keys and the loop applies the eviction
        // here where `&mut bindings` is held.
        if !deleted_synced_keys.is_empty() {
            invalidate_flow_cache_slots_for_deleted_sessions(&mut bindings, &deleted_synced_keys);
        }
        // #10612: a stale replay can be queued after the rotation purge and
        // must be refused before worker installation. Remove the same stale
        // row from shared authority as well, but only while it still has the
        // stale zone identity: a legitimate live replacement under the same
        // key must not be deleted by a delayed stale command. Single pass per
        // key (R-N2C: snapshot the forward NAT BEFORE evicting, so the derived
        // reverse companion is always available — a separate second loop would
        // read-after-delete and never fire).
        for key in &stale_replay_dropped_keys {
            // Snapshot the forward's NAT first (None if the key is already
            // gone or reversed — both safe to skip). #2402: recover the lock
            // (never skip on poison).
            let companion_key = {
                let map = crate::afxdp::shared_ops::lock_shared_recover(&shared_sessions);
                map.get(key)
                    .filter(|entry| !entry.metadata.is_reverse)
                    .map(|entry| {
                        crate::session::reverse_session_key(&entry.key, entry.decision.nat)
                    })
            };
            let _ = crate::afxdp::shared_ops::remove_shared_session_if(
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                key,
                |entry| {
                    crate::afxdp::session_glue::synced_entry_is_stale_replay(
                        entry.origin,
                        &entry.metadata,
                        forwarding.as_ref(),
                    )
                },
            );
            // #10612 (N2 companion): evict the derived reverse companion too
            // (mirrors the coordinator purge) so an unqueued stale reverse half
            // does not linger shared-side until next bringup.
            if let Some(reverse_key) = companion_key {
                let _ = crate::afxdp::shared_ops::remove_shared_session_if(
                    &shared_sessions,
                    &shared_nat_sessions,
                    &shared_forward_wire_sessions,
                    &shared_owner_rg_indexes,
                    &reverse_key,
                    |entry| {
                        crate::afxdp::session_glue::synced_entry_is_stale_replay(
                            entry.origin,
                            &entry.metadata,
                            forwarding.as_ref(),
                        )
                    },
                );
            }
        }
        if !shaped_tx_requests.is_empty() {
            apply_worker_shaped_tx_requests(
                &mut bindings,
                forwarding.as_ref(),
                &binding_lookup,
                loop_now_ns,
                shaped_tx_requests,
                &mut shared_recycles,
            );
            apply_shared_recycles_to_bindings(&mut bindings, &binding_lookup, &mut shared_recycles);
        }
        if !cancelled_keys.is_empty() {
            for key in &cancelled_keys {
                for binding in bindings.iter_mut() {
                    cancel_queued_flow_on_binding(binding, key, key, Some(&mut shared_recycles));
                }
                apply_shared_recycles_to_bindings(
                    &mut bindings,
                    &binding_lookup,
                    &mut shared_recycles,
                );
                if let Some((decision, metadata, origin)) = sessions.entry_with_origin(key) {
                    // Demotion keeps the session in the standby table, but the
                    // stale owner must stop advertising local XSK redirect
                    // aliases immediately or XDP will keep steering packets to
                    // the old node after RG handoff.
                    delete_session_map_redirect_for_session(
                        session_map.handle(),
                        key,
                        decision,
                        &metadata,
                        origin,
                    );
                }
            }
        }
        heartbeat.store(loop_now_ns, Ordering::Relaxed);
        // #13075: the housekeeping fn cannot see the loop-local flush
        // macro, so it flushes through this closure over
        // flush_session_deltas_loop (the macro as a fn). Sessions/bindings
        // arrive per call from the housekeeping fn — capturing them here
        // would conflict with passing them to that same call.
        let forwarding_for_flush = forwarding.clone();
        let mut flush_deltas = |sessions: &mut crate::session::SessionTable,
                                bindings: &mut [BindingWorker],
                                wedged: &mut bool,
                                deltas: &[SessionDelta]| {
            flush_session_deltas_loop(
                sessions,
                bindings,
                session_map.handle(),
                conntrack_v4_fd,
                conntrack_v6_fd,
                &dnat_fds,
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &recent_session_deltas,
                &peer_worker_commands,
                &worker_commands_by_id,
                &event_stream,
                forwarding_for_flush.as_ref(),
                &shared_runtime,
                wedged,
                worker_id,
                deltas,
            );
        };
        // #13075: expiry/GC housekeeping (HA retention ctx, expiry walk,
        // PPTP forget, seed retirement, reap, close-delta drain) lives in
        // housekeeping.rs. `true` = deferred cleanup: skip the rest of
        // this tick (the old in-block `continue` sites).
        if run_session_housekeeping(
            &mut sessions,
            &mut bindings,
            &binding_lookup,
            forwarding.as_ref(),
            &ha_runtime,
            loop_now_ns,
            loop_now_secs,
            &rg_epochs,
            session_map.handle(),
            conntrack_v4_fd,
            conntrack_v6_fd,
            worker_id,
            &pptp_control,
            worker_commands_by_id.get(&worker_id),
            &peer_worker_commands,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &shared_runtime,
            &mut worker_lossless_wedged,
            &mut shared_recycles,
            &mut deferred_expiry_overflow_deltas,
            &mut flush_deltas,
        ) {
            continue;
        }
        // #13075: PPTP control-inbox drain (pptp_drain.rs), immediately
        // after the expiry housekeeping above — see that file for the
        // #7699 placement contract.
        run_pptp_control_drain(
            &pptp_control,
            &mut sessions,
            &commands,
            &peer_worker_commands,
            loop_now_ns,
        );
        // #13075: conntrack-refresh slice + fabric/WG drains (ct_slice.rs).
        run_ct_slice(
            &sessions,
            &mut forwarding,
            loop_now_ns,
            conntrack_v4_fd,
            conntrack_v6_fd,
            &mut ct_refresh_cursor,
            &mut ct_cycle_start_ns,
            &mut last_ct_slice_ns,
            &mut wr_counters.session_volume_high_water,
            &shared_fabrics,
            &wg_uncovered_queues,
            &mut wg_uncovered_batch,
            worker_id,
        );
        // #7201: a command backlog IS work. `apply_worker_commands` drains at
        // most `WORKER_COMMAND_DRAIN_BUDGET` per pass so the AF_XDP rings get
        // serviced between slices; the remainder is only reachable if this loop
        // comes straight back. Left out of `did_work` — which `poll_binding`
        // alone would set — a promoted standby with no traffic yet runs
        // `idle_iters` past `IDLE_SPIN_ITERS` and puts every remaining slice
        // behind a 1 ms `poll(2)`, so the budget would trade a bounded 3.85 ms
        // stall for ~16 ms of drain. Seeded here rather than OR-ed after the
        // sweep so there is one assignment to reason about.
        let mut did_work = commands_backlogged || !session_import_repairs.is_empty();
        let mut dbg_poll = DebugPollCounters::default();
        // #1620: read the cold-path sample mask from forwarding state once
        // per poll cycle (rather than per-binding) — it's a daemon-wide
        // setting and rarely changes. Workers load the ArcSwap-protected
        // forwarding state above so this is L1-hot.
        let cold_path_sample_mask = forwarding.cold_path_sample_mask;
        for offset in 0..bindings.len() {
            let idx = if bindings.is_empty() {
                0
            } else {
                (poll_start + offset) % bindings.len()
            };
            let injected_packet = loop {
                let Some(descriptor) = wg_uncovered_batch.next() else {
                    break None;
                };
                let rx_queue_index = bindings
                    .get(idx)
                    .map(|binding| binding.queue_id)
                    .unwrap_or(worker_id);
                if let Some(packet) = crate::afxdp::wg_uncovered_forward::build_injected_packet(
                    &descriptor,
                    &forwarding,
                    validation,
                    rx_queue_index,
                ) {
                    break Some(packet);
                }
            };
            if poll_binding(
                idx,
                &mut bindings,
                &binding_lookup,
                mirror_targets.as_ref(),
                &mut sessions,
                &mut screen_state,
                validation,
                loop_now_ns,
                loop_now_secs,
                ha_startup_grace_until_secs,
                &forwarding,
                ha_runtime.as_ref(),
                &dynamic_neighbors,
                &pptp_control,
                neighbor_resolver.as_ref(),
                &shared_sessions,
                &shared_nat_sessions,
                &shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &ike_exchanges,
                slow_path.as_ref(),
                event_stream.as_ref(),
                &local_tunnel_deliveries,
                &recent_exceptions,
                &recent_session_deltas,
                &last_resolution,
                &peer_worker_commands,
                worker_id,
                worker_commands_by_id.as_ref(),
                &mut shared_recycles,
                &dnat_fds,
                conntrack_v4_fd,
                conntrack_v6_fd,
                &mut dbg_poll,
                &rg_epochs,
                cold_path_sample_mask,
                injected_packet,
            ) {
                did_work = true;
            }
        }
        crate::filter::flush_recorded_filter_counters();
        // #3073: fold this worker's coalesced policy hit-count tally into the
        // shared counters once per RX batch (alongside the filter-counter
        // flush) so `show security policies hit-count` converges within a tick.
        crate::policy::flush_recorded_policy_hit_counters();
        // #3651: fold this worker's coalesced per-zone traffic tally into the
        // shared zone-counter store, same cadence. `forwarding` is stable
        // across this iteration's binding sweep, so the slot map matches the
        // one the `record_zone_traffic` calls used.
        // #5163: the fold is lock-free — it `fetch_add`s into the slot map's
        // cached per-zone atomics, so this per-batch call no longer takes the
        // shared store mutex that every worker used to bounce at line rate.
        crate::afxdp::zone_counters::flush_recorded_zone_counters(
            &forwarding.zone_counter_store,
            &forwarding.zone_counter_slot_map,
        );
        // #3651: and this worker's coalesced per-zone flood-EVENT tally. Same
        // cadence and same `forwarding` snapshot, so the slot map matches the
        // one the `record_screen_drop` calls resolved their slots against.
        // Coalesced rather than folded at the drop site because a SYN flood is
        // the primary screen-drop trigger: at attack rate every worker would be
        // `fetch_add`ing the SAME zone's cache line per packet (#1187).
        crate::afxdp::flood_counters::flush_recorded_flood_counters(
            &forwarding.flood_counter_store,
            &forwarding.flood_counter_slot_map,
        );
        #[cfg(feature = "debug-log")]
        {
            dbg.accumulate(&dbg_poll);
        }
        if !bindings.is_empty() {
            poll_start = (poll_start + 1) % bindings.len();
        }
        if loop_now_ns.saturating_sub(last_cos_status_ns) >= COS_STATUS_INTERVAL_NS {
            cos_status.store(Arc::new(build_worker_cos_statuses(
                &bindings,
                forwarding.as_ref(),
                loop_now_ns,
            )));
            last_cos_status_ns = loop_now_ns;
        }
        // #13075: delta-loss resync + delete-drop/install-table sweeps
        // in delta_recovery.rs. `true` = deferred cleanup: skip tick.
        if run_delta_recovery(
            &mut sessions,
            &mut bindings,
            &binding_lookup,
            forwarding.as_ref(),
            validation.fib_generation,
            worker_id,
            loop_now_ns,
            conntrack_v4_fd,
            conntrack_v6_fd,
            &peer_worker_commands,
            worker_export.is_none(),
            session_map.handle(),
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &mut last_delete_drop_epoch,
            &mut delete_drop_sweep,
            &mut install_table_purge,
            &mut shared_recycles,
            &shared_runtime,
            &mut worker_lossless_wedged,
            &mut flush_deltas,
        ) {
            continue;
        }
        // #7919: publish this tick's per-session counter answers into the
        // worker's reply slots. Answer fields FIRST, then the sequence with
        // Release — the reader loads the sequence with Acquire and only then
        // reads the answers, so the sequence IS the ack and there is no second
        // completion flag to disagree with it.
        for answer in &session_counter_answers {
            runtime_atomics
                .counter_query_found
                .store(u64::from(answer.found), Ordering::Relaxed);
            runtime_atomics
                .counter_query_replica
                .store(u64::from(answer.replica), Ordering::Relaxed);
            runtime_atomics
                .counter_query_fwd_packets
                .store(answer.fwd_packets, Ordering::Relaxed);
            runtime_atomics
                .counter_query_fwd_bytes
                .store(answer.fwd_bytes, Ordering::Relaxed);
            runtime_atomics
                .counter_query_rev_packets
                .store(answer.rev_packets, Ordering::Relaxed);
            runtime_atomics
                .counter_query_rev_bytes
                .store(answer.rev_bytes, Ordering::Relaxed);
            runtime_atomics
                .counter_query_seq
                .store(answer.sequence, Ordering::Release);
        }
        // #9856 M2c: multi-pass resumable CommandExport. New commands adopt
        // (overwrite: single-window invariant — concurrent kicks never reach
        // here, coordinator BUSY); an in-progress window resumes. Every active
        // pass drains first so the ring starts empty, then runs ONE budgeted
        // slice: direct conversion into the worker's export buffer (the
        // control leg) + paced ring+flush echo (binding/recent consumers still
        // run; the event-stream HA/RT_FLOW echo is suppressed for CommandExport
        // provenance per #9630). Backpressure (Full), emit cap, slice
        // budget, or deadline pauses WITHOUT advancing past the failed slot;
        // completion acks and clears.
        // #13075: #9856 CommandExport slice + steady-state delta drain
        // in export_slice.rs. (skip_tick, did_work_delta): skip_tick is
        // the old in-block `continue`; did_work_delta marks export work.
        let (skip_export_tick, export_did_work) = run_export_slice(
            &mut sessions,
            &mut bindings,
            &binding_lookup,
            forwarding.as_ref(),
            &mut worker_export,
            exported_sequences,
            export_owner_rgs,
            export_kick_epoch,
            &export_buffer,
            &mut export_echo_scratch,
            &mut shared_recycles,
            &shared_runtime,
            &shared_sessions,
            &shared_owner_rg_indexes,
            &session_export_ack,
            worker_id,
            &mut flush_deltas,
            &mut worker_lossless_wedged,
        );
        if export_did_work {
            did_work = true;
        }
        if skip_export_tick {
            continue;
        }
        // #9856: tombstones are useful only while an export window is active.
        // Drop idle removals every tick so terminal-session churn cannot retain
        // cloned metadata until an unrelated future export. A fresh command
        // clears once at acceptance (the command handler), while a completed
        // window clears here after its final harvest.
        if worker_export.is_none() {
            sessions.discard_tombstones_for_export();
        }
        // Debug: periodic summary report
        {
            let elapsed = loop_now_ns.saturating_sub(dbg_last_report_ns);
            if elapsed >= DBG_REPORT_INTERVAL_NS {
                #[cfg(feature = "debug-log")]
                let session_count = sessions.len();
                // #5189 (A1-b8-F5): the per-binding diagnostics string is built
                // ONLY under `debug-log`. It used to be built unconditionally —
                // a `String` + per-binding `statistics_v2()` and `SO_ERROR`
                // getsockopt syscalls every ~1 s per worker in release builds,
                // where the only consumer (`emit_periodic_report`) is compiled
                // out. Release health is published as fixed scalar atomics by
                // the always-on `BindingLiveState` loop below (#802/#878).
                #[cfg(feature = "debug-log")]
                let binding_summary = debug_report::build_binding_summary(&bindings, &mut dbg);
                // #1776: the cfg(debug-log) verbose per-second report —
                // the giant DBG summary eprintln + degraded-path dump —
                // lives in debug_report.rs. Release builds skip it, as
                // before. #5189 (A1-b8-F5) moved the `binding_summary`
                // build that feeds it into the same gated module, so a
                // release build no longer pays for a string nothing reads.
                #[cfg(feature = "debug-log")]
                debug_report::emit_periodic_report(
                    worker_id,
                    elapsed,
                    &dbg,
                    session_count,
                    &bindings,
                    &binding_summary,
                );
                // Save prev counters BEFORE reset for stall detection below
                #[cfg(feature = "debug-log")]
                let (prev_rx_total, prev_fwd_total) = (dbg.rx_total, dbg.forward_total);
                dbg_last_report_ns = loop_now_ns;
                // #1776 (plan v3.1 AGY CORRECTNESS-1 guard): DbgCounters
                // holds ONLY per-interval counters, so this single-line
                // reset must NOT touch the persistent debug state —
                // dbg_last_report_ns (re-armed above) and the cross-
                // interval stall baselines stall_prev_fwd /
                // stall_reported, which live in plain locals; the
                // same-interval prev_rx_total / prev_fwd_total snapshot
                // was taken from `dbg` above, BEFORE this reset.
                #[cfg(feature = "debug-log")]
                {
                    dbg = debug_report::DbgCounters::default();
                }
                // Stall detection: stall_prev_fwd is PREVIOUS interval's fwd count,
                // prev_fwd_total is THIS interval's fwd count (saved before reset).
                #[cfg(feature = "debug-log")]
                debug_report::check_and_dump_stall(
                    worker_id,
                    prev_rx_total,
                    prev_fwd_total,
                    &mut stall_prev_fwd,
                    &mut stall_reported,
                    session_count,
                    &bindings,
                    &sessions,
                );
                screen_status::publish_screen_state_status(&screen_state, &bindings);
                for b in bindings.iter_mut() {
                    // #802: publish ring-pressure counters into BindingLiveState
                    // BEFORE resetting the worker-local window. The worker-local
                    // counters (b.telemetry.dbg_tx_ring_full, etc.) are accumulated by the
                    // hot path and reset each ~1s debug tick; without this
                    // publish they'd never be visible outside the worker thread.
                    // fetch_add is used because the atomic holds the cumulative
                    // total while the local counter holds only the current
                    // window. Relaxed is sufficient — diagnostic counters, no
                    // synchronization contract.
                    if b.telemetry.dbg_tx_ring_full != 0 {
                        b.live
                            .dbg_tx_ring_full
                            .fetch_add(b.telemetry.dbg_tx_ring_full, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_sendto_enobufs != 0 {
                        b.live
                            .dbg_sendto_enobufs
                            .fetch_add(b.telemetry.dbg_sendto_enobufs, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_bound_pending_overflow != 0 {
                        b.live
                            .dbg_bound_pending_overflow
                            .fetch_add(b.telemetry.dbg_bound_pending_overflow, Ordering::Relaxed);
                    }
                    if b.telemetry.dbg_cos_queue_overflow != 0 {
                        b.live
                            .dbg_cos_queue_overflow
                            .fetch_add(b.telemetry.dbg_cos_queue_overflow, Ordering::Relaxed);
                    }
                    // #802: kernel xdp_statistics are already absolute
                    // (kernel-cumulative), so they are published with store()
                    // not fetch_add. Sampling failures are silently ignored —
                    // the atomics simply retain their last good value.
                    //
                    // #9168: this site used to store ONE of the six counters
                    // `statistics_v2()` returns and discard the other five, two
                    // of which (`rx_dropped`, `rx_invalid_descs`) were plumbed
                    // all the way to the operator's `Kernel RX dropped:` /
                    // `Kernel RX invalid:` lines and therefore reported a
                    // permanent hard 0 — the healthy value, on the instrument
                    // that exists to reveal a NIC dropping every packet. The
                    // whole sample now goes to one publisher, which destructures
                    // it exhaustively so a future field cannot be dropped here
                    // silently.
                    if let Ok(stats) = b.xsk.device.statistics_v2() {
                        b.live.publish_kernel_xdp_statistics(stats);
                    }
                    // #802: outstanding_tx is a transient gauge on
                    // BindingWorker.tx_pipeline (current in-flight TX).
                    // Publish to the existing atomic mirror on
                    // BindingLiveState so the snapshot reader sees a
                    // recent value. store() because it's a gauge, not a
                    // counter. (#959 Phase 10 moved the field from
                    // BindingWorker to WorkerTxPipeline.)
                    b.live
                        .debug_outstanding_tx
                        .store(b.tx_pipeline.outstanding_tx, Ordering::Relaxed);
                    publish_tx_completion_ring_telemetry(&b.live, &mut b.telemetry);
                    // #878: publish UMEM in-flight gauge as a single atomic
                    // so the daemon's `show chassis forwarding` Buffer% can
                    // divide by `umem_total_frames` without torn-load risk.
                    // Computed in this thread from worker-local state, so
                    // the inputs are mutually consistent at sample time.
                    //
                    // "Idle" frames are: free_tx_frames (worker's TX-available
                    // pool), pending_fill_frames (worker's queue waiting to
                    // push to the kernel's fill ring), AND fill_pending (the
                    // kernel's fill ring itself, which holds frames the
                    // kernel can place RX data into — those are NOT in
                    // flight). Without subtracting fill_pending the gauge
                    // reads ~70-80% at idle because AF_XDP keeps the fill
                    // ring pre-populated by design.
                    let total = b.umem.total_frames();
                    let free_tx = b.tx_pipeline.free_tx_frames.len() as u32;
                    let pending_fill = b.tx_pipeline.pending_fill_frames.len() as u32;
                    let kernel_fill = b.xsk.device.pending();
                    let inflight = total
                        .saturating_sub(free_tx)
                        .saturating_sub(pending_fill)
                        .saturating_sub(kernel_fill);
                    b.live
                        .umem_inflight_frames
                        .store(inflight, Ordering::Relaxed);

                    b.telemetry.dbg_fill_submitted = 0;
                    b.telemetry.dbg_fill_failed = 0;
                    b.telemetry.dbg_poll_cycles = 0;
                    b.telemetry.dbg_backpressure = 0;
                    b.telemetry.dbg_rx_empty = 0;
                    b.telemetry.dbg_rx_wakeups = 0;
                    b.telemetry.dbg_tx_ring_submitted = 0;
                    b.telemetry.dbg_tx_ring_full = 0;
                    b.telemetry.dbg_completions_reaped = 0;
                    b.telemetry.dbg_sendto_calls = 0;
                    b.telemetry.dbg_sendto_err = 0;
                    b.telemetry.dbg_sendto_eagain = 0;
                    b.telemetry.dbg_sendto_enobufs = 0;
                    b.telemetry.dbg_bound_pending_overflow = 0;
                    b.telemetry.dbg_cos_queue_overflow = 0;
                    #[cfg(feature = "debug-log")]
                    {
                        b.telemetry.dbg_tx_tcp_rst = 0;
                    }
                    b.telemetry.dbg_rx_avail_nonzero = 0;
                    b.telemetry.dbg_rx_avail_max = 0;
                    b.telemetry.dbg_rx_wake_sendto_ok = 0;
                    b.telemetry.dbg_rx_wake_sendto_err = 0;
                    b.telemetry.dbg_rx_wake_sendto_errno = 0;
                }
            }
        }
        if did_work {
            idle_iters = 0;
            // #869: classify this iteration for next-loop-top accounting.
            wr_state = WorkerRuntimeState::Active;
            wr_counters.work_loops = wr_counters.work_loops.wrapping_add(1);
            continue;
        }
        idle_iters = idle_iters.saturating_add(1);
        wr_counters.idle_loops = wr_counters.idle_loops.wrapping_add(1);
        match poll_mode {
            crate::PollMode::BusyPoll => {
                if idle_iters <= IDLE_SPIN_ITERS {
                    wr_state = WorkerRuntimeState::IdleSpin;
                    std::hint::spin_loop();
                } else {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    thread::sleep(Duration::from_micros(IDLE_SLEEP_US));
                }
            }
            crate::PollMode::Interrupt => {
                // Interrupt mode still needs a short local spin before blocking.
                // Firewall-local TCP flows are ACK-latency-sensitive; blocking
                // immediately on the first empty poll collapses cwnd badly.
                if idle_iters <= IDLE_SPIN_ITERS {
                    wr_state = WorkerRuntimeState::IdleSpin;
                    std::hint::spin_loop();
                } else if !interrupt_poll_fds.is_empty() {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    for pfd in &mut interrupt_poll_fds {
                        pfd.revents = 0;
                    }
                    let rc = unsafe {
                        libc::poll(
                            interrupt_poll_fds.as_mut_ptr(),
                            interrupt_poll_fds.len() as libc::nfds_t,
                            INTERRUPT_POLL_TIMEOUT_MS,
                        )
                    };
                    // #6431: this blocking poll is the ONLY backoff Interrupt
                    // mode has past the spin window, so discarding its return
                    // is not a cosmetic omission — a return that came back
                    // IMMEDIATELY (a hard errno, or a revents set carrying
                    // only POLLNVAL/POLLERR/POLLHUP) repeats at syscall rate
                    // and turns the idle wait into a hot spin on a pinned
                    // core. Capture errno BEFORE anything else can clobber it.
                    let errno = if rc < 0 {
                        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                    } else {
                        0
                    };
                    match idle_poll::classify(rc, errno, &interrupt_poll_fds) {
                        // Timeout or a readable queue: the wait waited.
                        idle_poll::IdlePoll::Waited => {}
                        // EINTR: retry. The next loop pass re-enters the poll,
                        // so the retry costs one work scan and no sleep.
                        idle_poll::IdlePoll::Interrupted => {}
                        idle_poll::IdlePoll::Degraded => {
                            if !idle_poll_degraded {
                                idle_poll_degraded = true;
                                let faults = idle_poll::fault_summary(&interrupt_poll_fds);
                                eprintln!(
                                    "xpf-dp: w{worker_id}: idle poll degraded \
(rc={rc} errno={errno}{}{}) — substituting a {INTERRUPT_POLL_TIMEOUT_MS}ms sleep \
so the idle path cannot spin; RX is unaffected (the rings are still swept every \
pass). Logged once per worker.",
                                    if faults.is_empty() { "" } else { " " },
                                    faults,
                                );
                            }
                            // Restore the duty cycle the healthy path has.
                            thread::sleep(Duration::from_millis(INTERRUPT_POLL_TIMEOUT_MS as u64));
                        }
                    }
                } else {
                    wr_state = WorkerRuntimeState::IdleBlock;
                    thread::sleep(Duration::from_millis(INTERRUPT_POLL_TIMEOUT_MS as u64));
                }
            }
        }
    }
    crate::filter::flush_recorded_filter_counters();
    // #3073: final flush on worker exit (mirrors the filter-counter flush).
    crate::policy::flush_recorded_policy_hit_counters();
    for binding in bindings.iter_mut() {
        clear_all_cos_exact_backlogs_for_binding(binding);
        release_all_cos_root_leases(binding);
        release_all_cos_queue_leases(binding);
    }
    cos_status.store(Arc::new(build_worker_cos_statuses(
        &bindings,
        forwarding.as_ref(),
        monotonic_nanos(),
    )));
    heartbeat.store(monotonic_nanos(), Ordering::Relaxed);
}
