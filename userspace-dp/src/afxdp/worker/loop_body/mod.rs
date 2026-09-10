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

// #1776: the one-shot setup phase (thread pin, TSC calibration,
// initial ArcSwap load_fulls, binding construction, BPF-map-FD
// cache, initial cos_status publish) lives in loop_body/setup.rs.
mod setup;

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

/// #6592: refresh the worker's per-tick `(validation, forwarding)` view from
/// ONE `ArcSwap` load, so the two halves can never come from different
/// generations.
///
/// # What went wrong with two loads
///
/// Validation and forwarding used to live in two independent `ArcSwap`s, and
/// this refresh performed two separate acquire-loads. A coordinator publish
/// landing between them left the worker holding one half from generation N and
/// the other from N-1 — a torn pair, unsafe in BOTH orientations:
/// - `(old validation, new forwarding)` — a packet stamped at the OLD
///   generation matches the worker's old validation, classifies `Valid`
///   (`classify_metadata`, `forwarding/fib.rs`), and is then forwarded under
///   the NEW tables. This is what #6291 named.
/// - `(new validation, old forwarding)` — the mirror. While the shim is still
///   stamping the OLD generation this pair only drops
///   (`ConfigGenerationMismatch`, or `FibGenerationMismatch` when only the FIB
///   generation moved). But once the coordinator's reply reaches Go and Go
///   writes the new generation to `userspace_ctrl`, the shim stamps NEW; those
///   packets match the worker's new validation, classify `Valid`, and are
///   forwarded under the STALE tables — a withdrawn route still resolves, a
///   newly added deny is not applied. Nothing orders the Go control-map update
///   after every worker's next forwarding load. This is #6592.
///
/// Reordering the two loads cannot fix this. Producer and consumer must run in
/// OPPOSITE orders for an acquire/release pair, which excludes exactly one of
/// the two orientations and widens the other. #6291's reorder closed the first
/// and left the second — and the second is the COMMON one: it needs only the
/// forwarding load to land anywhere inside the publish window, whereas the
/// closed orientation needed the whole window (a full `ForwardingState` clone —
/// 69 fields, ~20 heap-owning collections including the FIB) to nest inside the
/// nanosecond-scale gap between two adjacent loads, i.e. a stalled worker.
///
/// # What one load buys
///
/// The coordinator publishes a single [`RuntimeView`] holding both halves
/// (`Coordinator::publish_runtime_view`). Whichever view this load observes,
/// its `validation` and `forwarding` were published together, so the returned
/// pair is coherent by construction. Neither orientation is reachable; there is
/// no pair to tear and no ordering discipline to get wrong.
///
/// Observing an OLD view is still possible and still SAFE: new-stamped packets
/// mismatch the old validation and DROP, the intended fail-closed behaviour.
/// This closes INCOHERENT pairs, not stale coherent ones — nothing here forces
/// a refresh.
///
/// # Cost
///
/// One `ArcSwap` load per tick where there used to be two, and the #1188
/// short-circuit is preserved exactly: `Arc::ptr_eq` against the caller's
/// cached forwarding returns `None` when the published forwarding `Arc` did not
/// rotate, so the caller's expensive rotation branch is skipped. A
/// validation-only publish (`bump_fib_generation`) rotates the view but reuses
/// the inner forwarding `Arc`, so it still short-circuits — see
/// `Coordinator::republish_runtime_validation`. The #5166 CoS pair is unchanged:
/// the caller still reads this view before the CoS map Arcs.
///
/// `between` is a deterministic test seam fired between reading the two halves
/// OUT of the loaded view. Under this implementation both reads come from the
/// same already-loaded `Arc`, so a coordinator publish injected there is
/// invisible and the returned pair stays coherent. Splitting the refresh back
/// into two `ArcSwap` loads — in EITHER order — makes an injected publish tear
/// the pair, which is exactly what
/// `snapshot_refresh_runtime_view_pair_is_atomic_6592` asserts against.
/// Production passes `|_| {}`: a ZST whose `call_once` body is empty, so
/// `#[inline]` collapses this to the single load in release builds — no
/// per-tick call boundary or cost (the loop deliberately stays inline; see the
/// module header).
///
/// It takes the just-read `ValidationState` as an argument for one reason: that
/// makes the seam's POSITION a compile-time fact. The producer-side seam proves
/// its own position by retaining the pre-store view (a hoist above the store is
/// RED); the consumer seam needs the same defence, because a `between` hoisted
/// above the load would let the injected publish land before ANY read and the
/// test would pass vacuously on an old-old pair. Passing a value that only
/// exists after the load makes that hoist fail to compile rather than pass
/// silently. The argument is unused in production (`|_| {}`).
///
/// LIMIT, stated rather than left implicit: this seam pins the ordering INSIDE
/// this function, and the test drives this function rather than the real
/// `worker_loop`. A SECOND `shared_runtime.load()` added elsewhere in the tick
/// would pair halves across generations without tripping the test. That hole is
/// covered mechanically instead, by the reader-load count in
/// `tests/runtime_view_publish_canary.rs`.
#[inline]
fn refresh_runtime_view(
    forwarding: &Arc<ForwardingState>,
    shared_runtime: &RuntimeViewReader,
    between: impl FnOnce(ValidationState),
) -> (Option<Arc<ForwardingState>>, ValidationState) {
    // ONE acquire-load. Everything below reads out of `view`, so the two
    // halves are from the same publish no matter what runs concurrently.
    let view = shared_runtime.load();
    let validation = view.validation();
    between(validation);
    // #1188: adopt the forwarding Arc only when it actually rotated.
    let new_forwarding = if Arc::ptr_eq(forwarding, view.forwarding()) {
        None
    } else {
        Some(view.forwarding().clone())
    };
    (new_forwarding, validation)
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
        session_map_fd,
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
    const COS_STATUS_INTERVAL_NS: u64 = 100_000_000;
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
    macro_rules! flush_drained_session_deltas {
        ($deltas:expr) => {{
            let deltas_ref: &[SessionDelta] = $deltas;
            let event_stream_out_of_sync = match bindings.first() {
                Some(binding) => {
                    let ident = binding.identity();
                    flush_session_deltas(
                        &ident,
                        Some(&binding.live),
                        binding.bpf_maps.session_map_fd,
                        conntrack_v4_fd,
                        conntrack_v6_fd,
                        &dnat_fds,
                        deltas_ref,
                        &shared_sessions,
                        &shared_nat_sessions,
                        &shared_forward_wire_sessions,
                        &shared_owner_rg_indexes,
                        &recent_session_deltas,
                        &peer_worker_commands,
                        &worker_commands_by_id,
                        &event_stream,
                        forwarding.as_ref(),
                        &mut worker_lossless_wedged,
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
                        session_map_fd,
                        conntrack_v4_fd,
                        conntrack_v6_fd,
                        &dnat_fds,
                        deltas_ref,
                        &shared_sessions,
                        &shared_nat_sessions,
                        &shared_forward_wire_sessions,
                        &shared_owner_rg_indexes,
                        &recent_session_deltas,
                        &peer_worker_commands,
                        &worker_commands_by_id,
                        &event_stream,
                        forwarding.as_ref(),
                        &mut worker_lossless_wedged,
                    )
                }
            };
            if event_stream_out_of_sync {
                // #2874: a correctness-critical HA session open/close delta
                // could not be queued losslessly to the event-stream consumer.
                // Latch loss-of-sync so the `take_delta_loss` check below
                // re-exports the full owner-RG snapshot (the #2442 recovery
                // path), instead of silently leaving the peer short a session.
                sessions.set_delta_loss();
            }
        }};
    }
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
    while !stop.load(Ordering::Relaxed) {
        let loop_now_ns = monotonic_nanos();
        // #5468: reset the per-drain-cycle aggregate lossless-wedge latch. It is
        // threaded through every `flush_session_deltas` call this iteration (the
        // steady-state drain, the #2442 resync, and the #2653 export) so the
        // FIRST wedge caps the whole cycle's lossless wait at ~1 budget; a fresh
        // iteration must start un-wedged so a healthy consumer pays no penalty.
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
                // #7919: (no handle, stale handle, key mismatch)
                let (miss_nh, miss_sh, miss_km) = sessions.lookup_miss_counts();
                wr_counters.session_lookup_miss_no_handle = miss_nh;
                wr_counters.session_lookup_miss_stale_handle = miss_sh;
                wr_counters.session_lookup_miss_key_mismatch = miss_km;
                wr_counters.session_install_admission_refused = sessions.admission_refused();
                wr_counters.session_install_partial = sessions.install_partial();
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
            refresh_runtime_view(&forwarding, &shared_runtime, |_| {});
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

            // Use NEW values for dependent state updates (forwarding-site
            // ordering — old `forwarding` is stale once rotated).
            screen_state.update_profiles(new_forwarding.screen_profiles.clone());
            // #3082: re-thread the references-missing-profile set on every
            // runtime forwarding-snapshot rotation so a newly-introduced
            // dangling screen reference starts WARNing (and a fixed one stops).
            screen_state.update_missing_profiles(new_forwarding.screen_missing_profiles.clone());
            screen_state.update_inert_profiles(new_forwarding.screen_inert_profiles.clone());
            screen_state.update_syn_cookie_master_key(new_forwarding.syn_cookie_master_key.0);
            sessions.set_timeouts(new_forwarding.session_timeouts);
            // #3527: re-apply the per-screened-zone half-open overrides on every
            // runtime forwarding-snapshot rotation. `set_opening_overrides` is a
            // full replace, so a zone whose `syn-flood timeout` was removed
            // drops out and reverts to the global default on the next install.
            sessions.set_opening_overrides(new_forwarding.session_opening_overrides.clone());
            // #2134: re-derive the per-IP session-limit OFF-gate on every
            // runtime forwarding-snapshot rotation. A runtime ON->OFF
            // transition (operator removes `limit-session`) clears the
            // stale count maps via set_session_limit_active so a later
            // re-enable starts clean and cannot spuriously block an
            // under-limit IP.
            sessions.set_session_limit_active(screen_state.any_session_limit_configured());

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

            forwarding = new_forwarding;
            let purged_input_dscp = purge_sessions_for_input_dscp_filter_revalidation(
                &mut sessions,
                session_map_fd,
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
            if let Some(rule_id) = deleted_first_policy.as_deref() {
                let purged_first_policy = purge_sessions_bound_to_deleted_first_policy(
                    &mut sessions,
                    session_map_fd,
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
            let republished = republish_local_delivery_sessions_for_lo0_filter(
                &sessions,
                session_map_fd,
                &forwarding,
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
        let command_results = if has_commands {
            apply_worker_commands(
                &commands,
                &mut sessions,
                session_map_fd,
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
        let WorkerCommandResults {
            cancelled_keys,
            deleted_synced_keys,
            exported_sequences,
            session_counter_answers,
            export_owner_rgs,
            shaped_tx_requests,
            vacate_all_shared_exact_slots,
            commands_backlogged,
        } = command_results;
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
            invalidate_flow_cache_slots_for_deleted_sessions(
                &mut bindings,
                &deleted_synced_keys,
            );
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
                        session_map_fd,
                        key,
                        decision,
                        &metadata,
                        origin,
                    );
                }
            }
        }
        heartbeat.store(loop_now_ns, Ordering::Relaxed);
        // #2120: build the standby retention context so the wheel HOLDS
        // peer-synced sessions this node does not forward (restoring the
        // dead Go-GC `IsLocalPrimary` contract), self-heals them on RG
        // promotion (edge via rg_epochs), and reaps them at a bounded
        // ceiling if a primary delete is lost. The HA-forwarding logic
        // stays here (HAGroupRuntime's lease predicate is afxdp-private);
        // the session wheel only sees the closures + node_active.
        let ha_map = ha_runtime.as_ref();
        let rg_epochs_for_gate = &rg_epochs;
        // node_active: does this node forward at least one RG right now?
        // Excludes a standalone node (empty/all-inactive map) from ever
        // holding (mirrors session_glue's forwards-any pattern).
        let node_active = ha_map
            .values()
            .any(|group| group.is_forwarding_active(loop_now_secs));
        let forwards_rg = |rg: i32| -> bool {
            if rg > 0 {
                ha_map
                    .get(&rg)
                    .map(|group| group.is_forwarding_active(loop_now_secs))
                    .unwrap_or(false)
            } else {
                // owner_rg_id <= 0 (fabric / unresolved-owner reverse):
                // "forwards here" == the node forwards anything.
                node_active
            }
        };
        let epoch_of = |rg: i32| -> u32 {
            // A valid per-RG index uses rg_epochs[rg]; everything else
            // (rg <= 0 or out of range) uses the node-level rg_epochs[0]
            // activation edge. As of #2466 the flow-cache consumer guard
            // (flow_cache::rg_epoch_index) applies the SAME fallback, so the
            // two gates agree: an out-of-range owner RG (>= MAX_RG_EPOCHS) and
            // owner_rg_id == 0 (fabric / unresolved-owner reverse) both
            // self-heal on the node-level rg_epochs[0] edge rather than never.
            rg_epochs_for_gate[crate::afxdp::flow_cache::rg_epoch_index(rg)]
                .load(Ordering::Relaxed)
        };
        let ha_ctx = crate::session::ExpireHaContext {
            node_active,
            forwards_rg: &forwards_rg,
            epoch_of: &epoch_of,
            ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
            ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
        };
        let expired_entries = sessions.expire_stale_entries_ha(loop_now_ns, Some(&ha_ctx));
        // #2428: the "Current sessions" gauge Go derives as
        // (session_creates - session_expires) is a LOCAL-forwarding gauge.
        // `session_creates` is bumped ONLY on the four local poll-descriptor
        // install paths (ForwardFlow / ReverseFlow / LocalMiss /
        // MissingNeighborSeed). Every synced-derived origin (SyncImport /
        // SharedMaterialize / WorkerLocalImport / SharedPromote) is never
        // create-counted, so counting its expiry drives session_expires past
        // session_creates, wrapping the unsigned Go subtraction to ~1.8e19.
        // count_local_session_expiries (exhaustive match, no wildcard) counts
        // only the create-counted locals so accounting is balanced on the
        // SAME node and the standby gauge stays 0.
        let local_expired =
            count_local_session_expiries(expired_entries.iter().map(|e| e.origin));
        reap_expired_sessions(
            &mut bindings,
            &expired_entries,
            forwarding.as_ref(),
            session_map_fd,
            conntrack_v4_fd,
            conntrack_v6_fd,
            loop_now_ns,
            worker_id,
        );
        if local_expired > 0 {
            if let Some(binding) = bindings.first() {
                binding
                    .live
                    .session_expires
                    .fetch_add(local_expired, Ordering::Relaxed);
            }
        }
        // #7699: drain the PPTP control inbox — parse the TCP/1723 segments the
        // data path copied out, install the associations locally and publish
        // them to the sibling workers.
        //
        // PLACEMENT: adjacent to the association EXPIRY it is the counterpart
        // of, and on the same clock. This is per-iteration work only in the
        // sense that the CALL is; `take_pending` holds the drain-interval gate
        // ITSELF and returns an empty vec otherwise, so the body below runs
        // once per interval. The gate is deliberately not written here: this
        // loop runs at packet rate, and a call-site gate is one edit from
        // becoming per-poll work — which is exactly what #8399 shipped when the
        // association expiry landed above `expire_stale_entries_ha`'s gate
        // instead of below it. `worker_loop_drains_the_pptp_control_inbox_7699`
        // enforces both halves of that, including the absence of the interval
        // constant from this file — so do not name it here even in a comment.
        crate::afxdp::worker_queue::drain_pptp_control_inbox(
            &pptp_control,
            &mut sessions,
            &peer_worker_commands,
            loop_now_ns,
        );
        // Incrementally refresh last_seen in BPF conntrack entries so Go-side
        // callers of IterateSessions (CLI, gRPC, Prometheus) see accurate
        // session idle times.  Issue #333; budgeted/resumable per #5287.
        //
        // #5287: drive at most one budgeted slice per CT_SLICE_INTERVAL_NS.
        // `should_slice` is true while a cycle is in flight (cursor != 0, keep
        // draining the table) OR once the freshness window has elapsed since the
        // last cycle started (time to begin a fresh cycle). The `&&` short-
        // circuits on the cheap cursor compare in the common between-cycles idle
        // case, so the per-tick cost stays one integer compare plus one u64
        // subtract — no allocation, no regression to the empty/idle table.
        let should_slice = ct_refresh_cursor != 0
            || loop_now_ns.saturating_sub(ct_cycle_start_ns) >= CT_REFRESH_WINDOW_NS;
        if should_slice
            && loop_now_ns.saturating_sub(last_ct_slice_ns) >= CT_SLICE_INTERVAL_NS
        {
            last_ct_slice_ns = loop_now_ns;
            // Stamp the cycle start on the FIRST slice of a cycle (cursor at the
            // top) so successive cycles are paced to the freshness window.
            if ct_refresh_cursor == 0 {
                ct_cycle_start_ns = loop_now_ns;
            }
            let ct_outcome = refresh_bpf_conntrack_last_seen(
                conntrack_v4_fd,
                conntrack_v6_fd,
                &sessions,
                // #3395: re-resolve each live row's policy_id against the
                // current rule table from the session's bound rule handle.
                &forwarding.policy,
                loop_now_ns,
                ct_refresh_cursor,
                CT_REFRESH_SLICE_BUDGET,
            );
            ct_refresh_cursor = ct_outcome.cursor;
            // #7919: fold this slice's largest observed per-session volume into
            // the worker's monotonic high-water. The walk is budgeted, so a
            // single slice may miss a busy session; taking the max ACROSS
            // slices is what makes a reading of 0 mean "this worker's table has
            // never held a session with traffic" rather than "not in this
            // slice".
            wr_counters.session_volume_high_water = wr_counters
                .session_volume_high_water
                .max(ct_outcome.max_session_volume);
        }
        // Check if fabric links were updated by the coordinator (e.g. after
        // RG failover when peer MAC was resolved). If so, rebuild the
        // forwarding Arc with the new fabric links so fabric redirect works.
        {
            let live_fabrics = shared_fabrics.load();
            if !live_fabrics.is_empty() && live_fabrics.as_ref() != &forwarding.fabrics {
                let mut updated = (*forwarding).clone();
                updated.fabrics = live_fabrics.as_ref().clone();
                forwarding = Arc::new(updated);
            }
        }
        // #7201: a command backlog IS work. `apply_worker_commands` drains at
        // most `WORKER_COMMAND_DRAIN_BUDGET` per pass so the AF_XDP rings get
        // serviced between slices; the remainder is only reachable if this loop
        // comes straight back. Left out of `did_work` — which `poll_binding`
        // alone would set — a promoted standby with no traffic yet runs
        // `idle_iters` past `IDLE_SPIN_ITERS` and puts every remaining slice
        // behind a 1 ms `poll(2)`, so the budget would trade a bounded 3.85 ms
        // stall for ~16 ms of drain. Seeded here rather than OR-ed after the
        // sweep so there is one assignment to reason about.
        let mut did_work = commands_backlogged;
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
        // #2442: loss-of-sync resync. If `push_delta` dropped any delta since
        // the last drain, the in-worker session-delta ring overflowed and the
        // downstream session-sync consumer missed HA-relevant open/close
        // events — its view may have silently diverged from the table truth.
        // Re-emit an open delta for every owned forward session (the same
        // table-truth walk `ExportOwnerRGSessions` performs) so the peer
        // re-derives a complete snapshot.
        //
        // DRAIN-AS-YOU-EXPORT: a worker can own up to DEFAULT_MAX_SESSIONS
        // (131072) forward sessions — 32× the 4096-slot delta ring. A naive
        // "drain then push all N" overflows the ring at delta 4097, drops
        // sessions 4097..N, re-latches the loss, and never converges (a
        // permanent per-cycle resync storm). Instead, collect the candidates
        // once, then emit them in ring-sized chunks, draining+flushing each
        // chunk to the peer before emitting the next. The ring is empty before
        // every chunk and a chunk is < cap, so push_delta NEVER overflows
        // during a resync — the complete snapshot ships and the latch is not
        // spuriously re-armed. A genuinely new drop after the resync still
        // re-arms a fresh episode on a later cycle.
        //
        // Emit at most this many open deltas before draining. Comfortably
        // under MAX_SESSION_DELTAS (4096) so a freshly-emptied ring never
        // overflows mid-chunk. Shared by the #2442 loss-of-sync resync and the
        // #2653 single-shot `ExportOwnerRGSessions` command path.
        const RESYNC_EXPORT_CHUNK: usize = 2048;
        // Flush whatever is queued in the ring to the peer (shared with the
        // pre-export backlog drain and each chunk's post-emit drain).
        macro_rules! drain_and_flush_all {
            () => {
                while sessions.has_pending_deltas() {
                    let deltas = sessions.drain_deltas(256);
                    purge_queued_flows_for_closed_deltas(
                        &mut bindings,
                        &binding_lookup,
                        &mut shared_recycles,
                        &deltas,
                    );
                    // #2669: flush UNCONDITIONALLY. The binding-independent
                    // consumers (shared session/conntrack tables, HA peer,
                    // peer-worker commands, recent-deltas RPC buffer, event
                    // stream) must receive every drained delta even when no
                    // binding exists; only the per-binding RPC fallback push
                    // is gated on a binding. Gating the whole flush would
                    // drain-then-discard, silently desyncing HA/conntrack.
                    flush_drained_session_deltas!(&deltas);
                }
            };
        }
        // Chunked drain-as-you-export: collect the owned forward candidates
        // for `$owner_rgs` once, then emit them in ring-sized chunks, draining
        // and flushing each chunk to the peer before emitting the next. The
        // ring is empty before every chunk and a chunk is < cap, so
        // `push_delta` NEVER overflows during the export — the complete
        // snapshot ships and the loss latch is not spuriously re-armed. A
        // worker can own up to DEFAULT_MAX_SESSIONS (131072) forward sessions
        // — 32x the 4096-slot delta ring — so a naive "emit all N then drain
        // once" drops sessions 4097..N (the #2653 command-path bug, sibling of
        // #2442's worker-loop bug).
        macro_rules! chunked_drain_as_you_export {
            ($owner_rgs:expr) => {{
                let owner_rgs = $owner_rgs;
                if !owner_rgs.is_empty() {
                    let candidates = crate::afxdp::forward_export_candidates_for_owner_rgs(
                        &sessions, &owner_rgs,
                    );
                    for chunk in candidates.chunks(RESYNC_EXPORT_CHUNK) {
                        for (key, decision, metadata, origin) in chunk.iter().cloned() {
                            sessions
                                .emit_open_delta_with_origin(key, decision, metadata, origin, true);
                        }
                        // Ship this chunk and empty the ring before the next
                        // chunk, so the next batch of emits cannot overflow.
                        drain_and_flush_all!();
                    }
                }
            }};
        }
        // #5290: fold the per-binding RPC-fallback loss-of-sync latch into the
        // SessionTable latch. The control-thread fair drain
        // (`Coordinator::drain_session_deltas`) arms `BindingLiveState`'s latch
        // when the caller-wide budget overflowed and left this worker's deltas
        // undrained, and `push_session_delta` arms it when the per-binding
        // fallback buffer overflowed and dropped a delta. Either way the standby
        // missed HA-relevant open/close events, so drive the SAME #2442 owner-RG
        // resync below (table-truth rescan) — deliver-or-resync, never a silent
        // drop. A single AtomicBool per binding, so a burst raises exactly one
        // resync (debounced by the swap in `take_delta_loss`).
        for binding in &bindings {
            if binding.live.take_delta_loss() {
                sessions.set_delta_loss();
            }
        }
        // #8586: a cross-worker `DeleteSynced` for THIS worker was refused by a
        // full queue, so this worker never learned the session is gone. Its NAT
        // holder bit was already released on its behalf (#8576); what is left is
        // its own local table entry and its per-binding flow-cache slots, which
        // only this loop can reach — and the signal could not travel through the
        // queue that refused the command, hence the out-of-band epoch.
        //
        // KEYED ON THE DELETE DROP, NOT ON QUEUE PRESSURE, and that distinction
        // is measured rather than assumed: ordinary session establishment pins
        // the queue at the 4096 cap and discards 85,668 commands over 32,768
        // creates while dropping ZERO deletes (#8586). A trigger on queue depth
        // would run this walk continuously through normal traffic and reconcile
        // nothing.
        //
        // One relaxed load per pass. A burst raises exactly ONE reconcile per
        // pass however many refusals it caused, because the epoch is compared,
        // not counted down.
        let delete_drop_epoch =
            crate::afxdp::session_glue::session_delete_drop_epoch(worker_id);
        if delete_drop_epoch != last_delete_drop_epoch {
            last_delete_drop_epoch = delete_drop_epoch;
            // #9327: ARM the sweep; do not run it here. The whole-table walk
            // measured 6.47 ms at 60k sessions even when it finds NOTHING, and
            // 39 ms when everything is stale — against a ~1.97 ms RX-ring fill.
            // The epoch gate bounds how often this fires, not what one firing
            // costs, and one refused cross-worker DeleteSynced arms it.
            delete_drop_sweep.arm();
        }
        // Step the sweep every pass while it is running, bounded by
        // DELETE_DROP_SWEEP_BUDGET slab slots. A no-op with no sweep armed.
        {
            let mut evicted_keys: Vec<crate::session::SessionKey> = Vec::new();
            let reconciled =
                delete_drop_sweep.step(&mut sessions, &shared_sessions, &mut evicted_keys);
            if reconciled > 0 {
                crate::afxdp::worker::invalidate_flow_cache_slots_for_keys(
                    &mut bindings,
                    &evicted_keys,
                );
                debug_log!(
                    "DELETE_DROP_RECONCILE: worker={} epoch={} swept={}",
                    worker_id,
                    delete_drop_epoch,
                    reconciled,
                );
            }
        }
        if sessions.take_delta_loss() {
            // #2442 loss-of-sync resync. If `push_delta` dropped any delta
            // since the last drain, the in-worker session-delta ring
            // overflowed and the downstream session-sync consumer missed
            // HA-relevant open/close events — its view may have silently
            // diverged from the table truth. Re-emit an open delta for every
            // owned forward session so the peer re-derives a complete snapshot.
            //
            // Drain the existing backlog so the ring starts empty.
            drain_and_flush_all!();
            chunked_drain_as_you_export!(sessions.all_owner_rg_ids());
            // #8593: that claim was TRUE OF ONE RING AND FALSE OF THE OTHER,
            // and #5290 widened its scope without re-checking it. An earlier
            // revision read: "The export drained to empty without overflowing,
            // so any latch set during this resync was a genuinely-new local
            // drop, not the export re-flooding itself."
            //
            // `chunked_drain_as_you_export!` does keep the SessionTable ring
            // (`sessions.push_delta`) under its cap — that half is right. But
            // every chunk is then flushed through `flush_session_deltas` into
            // the PER-BINDING RPC-fallback buffer, which the chunking does not
            // drain and which the Go side polls on the ~5 s
            // `DrainSessionDeltas` cadence. #5290 later made THAT buffer's
            // overflow arm this same latch, so the export re-armed the trigger
            // that produced it.
            //
            // Measured on `loss:xpf-userspace-fw0`: 125,780 session creates
            // produced 25.26M deltas of which 23.29M (92%) were dropped, and
            // with the generator stopped and `active_flow_count = 0` the helper
            // kept generating ~149k deltas/s for ~90 s, ending only as the
            // owned sessions aged out. 32.68M dropped session-CREATE deltas
            // against 52k dropped closes, from 32,768 real creates — the
            // signature of re-exported opens, not of traffic.
            //
            // The export's own deltas now carry `SessionDelta::bulk_resync`
            // (set by their sole producer, `emit_open_delta_with_origin`), and
            // `flush_session_deltas` routes those to
            // `push_session_delta_bulk_export`, which counts a drop but does not
            // arm. The marker is on the DELTA rather than passed at this call
            // site on purpose: a future drain site that passed the flag wrongly
            // would SUPPRESS a genuine arm, silently, and here it does not
            // choose. So the claim above is true again, and for both rings: any
            // latch set from here on is a genuinely-new incremental drop.
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
        if !exported_sequences.is_empty() {
            // #2653 single-shot `ExportOwnerRGSessions` command path. The
            // command handler (`handle_export_owner_rg_sessions`) no longer
            // emits the open deltas itself — it only records the requested
            // owner RGs in `export_owner_rgs`. We perform the SAME chunked
            // drain-as-you-export here (where the binding + flush machinery
            // lives), so a worker owning more sessions than the 4096-slot ring
            // ships the COMPLETE bulk snapshot to the HA peer without dropping
            // sessions 4097..N. Drain any pre-export backlog first so the ring
            // starts empty, then export, then drain the final chunk's tail.
            drain_and_flush_all!();
            chunked_drain_as_you_export!(export_owner_rgs);
            drain_and_flush_all!();
            // Ack only after the complete export has drained to the peer.
            if let Some(sequence) = exported_sequences.iter().copied().max() {
                session_export_ack.store(sequence, Ordering::Release);
            }
        } else if sessions.has_pending_deltas() {
            let deltas = sessions.drain_deltas(256);
            purge_queued_flows_for_closed_deltas(
                &mut bindings,
                &binding_lookup,
                &mut shared_recycles,
                &deltas,
            );
            // #2669: flush unconditionally — see flush_drained_session_deltas!.
            flush_drained_session_deltas!(&deltas);
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
                        std::io::Error::last_os_error()
                            .raw_os_error()
                            .unwrap_or(0)
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
                            thread::sleep(Duration::from_millis(
                                INTERRUPT_POLL_TIMEOUT_MS as u64,
                            ));
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

/// #3776: apply the per-worker teardown side effects for every session the GC
/// wheel reaped this sweep — release its SNAT allocation, delete its BPF
/// redirect/conntrack entries, AND invalidate the per-worker flow-cache slot(s)
/// that back it.
///
/// The flow-cache invalidation is the half of #2220 that was never shipped.
/// #2220 (PR #2233) added only the keepalive: on a cache HIT the hot path
/// touches the backing session so an ACTIVELY-forwarding flow's session cannot
/// be reaped out from under a live cache entry. It does not cover a flow that
/// idles PAST its timeout — the GC reaps the session and releases its SNAT
/// port, but the flow-cache slot survives (config/fib generation, RG epoch, and
/// RG lease are all unchanged, and the slot is not LRU-evicted). If traffic
/// later resumes on the same 5-tuple it HITS the surviving `RewriteDescriptor`
/// and is forwarded WITHOUT a live session — a stateful-firewall bypass (no
/// policy re-evaluation, no session install, no `show security flow session`
/// row, not HA-synced) — and via a SNAT port that `release_source_nat_allocation`
/// may already have handed to a different flow (NAT-port reuse / reverse-path
/// collision). Evicting the slot here forces the next packet to MISS the cache
/// and re-run full session lookup/creation + policy (fail-closed: no forwarding
/// without a live session, no stale-SNAT reuse via a surviving descriptor).
/// Mirrors the RST-teardown eviction in `worker/lifecycle.rs`.
///
/// Cache ownership: the flow cache is per-binding and worker-owned, and this
/// runs on the owning worker's GC sweep, so the eviction is a same-thread
/// mutation — no cross-thread flush is needed. We invalidate on EVERY binding of
/// this worker because a reaped session does not carry the ingress ifindex the
/// cache is keyed on. That is both safe and precise: the session table is keyed
/// by the 5-tuple ALONE, so at most one live session — hence at most one VALID
/// descriptor — can exist for a given key, and `invalidate_slot` only drops a
/// slot whose key AND ingress_ifindex both match. On a non-owning binding the
/// call therefore either no-ops or drops a STALE prior-flow slot with the same
/// tuple (which should go anyway); it can never drop another live flow's entry.
/// Forward and reverse directions are each their own `ExpiredSession` with their
/// own key, so both directions' slots are covered. This is the reap path
/// (bounded by the ~1/s GC sweep), so it adds no per-packet cost and does not
/// regress the #2220 keepalive fast path.
#[allow(clippy::too_many_arguments)]
fn reap_expired_sessions(
    bindings: &mut [BindingWorker],
    expired_entries: &[crate::session::ExpiredSession],
    forwarding: &ForwardingState,
    session_map_fd: c_int,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    now_ns: u64,
    // #6211 F2: THIS worker's id, taken from `WorkerLaunchPlan::worker_id` at
    // the top of `worker_loop` — the worker's own identity established at
    // spawn, NOT read off a `BindingWorker` slot.
    //
    // This is the reap that motivates the whole holder set. Post-failover the
    // active's periodic `UpsertSynced` refresh stops and RSS lands traffic on
    // exactly ONE worker, so the other N-1 replicas of a synced session idle out
    // with nothing refreshing them. Whichever expires first must NOT free a
    // `(pool_addr, port)` the still-forwarding worker is using.
    worker_id: u32,
) {
    for expired_entry in expired_entries {
        release_source_nat_allocation_for_worker(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &expired_entry.key,
            expired_entry.decision.nat,
            expired_entry.metadata.is_reverse,
            now_ns,
            worker_id,
        );
        // #4381: return the reaped NAT64 forward flow's translated pool port to
        // its allocator (self-gated on the forward NAT64 entry).
        crate::nat64::release_nat64_allocation_for_worker(
            &forwarding.nat64,
            &expired_entry.key,
            expired_entry.decision.nat,
            expired_entry.metadata.is_reverse,
            now_ns,
            worker_id,
        );
        delete_session_map_entry_for_removed_session_with_origin(
            session_map_fd,
            &expired_entry.key,
            expired_entry.decision,
            &expired_entry.metadata,
            expired_entry.origin,
            conntrack_v4_fd,
            conntrack_v6_fd,
        );
        for binding in bindings.iter_mut() {
            binding
                .flow
                .flow_cache
                .invalidate_slot(&expired_entry.key, binding.ifindex);
        }
    }
}

/// #6457: invalidate the per-worker flow-cache slot(s) backing every session
/// a control-plane `WorkerCommand::DeleteSynced` dropped this tick.
///
/// This is the delete-path twin of #3776's GC-reap invalidation in
/// `reap_expired_sessions` above. Three control-plane flows funnel through
/// `DeleteSynced` — the operator's `clear security flow session [all]`
/// (`ClearAllSessions` / singular `DeleteSession` in the Go manager), the
/// cluster-stale sweep (`BatchDeleteSessions`), and HA DeleteSynced
/// propagation from the peer (`delete_synced_session_gen` fan-out plus
/// cross-worker `replicate_session_delete`). None of them bumps
/// config/fib generation, RG epoch, or RG lease, and none is an LRU
/// eviction, so without this eviction a revoked-but-still-active 5-tuple
/// kept HITTING its cached `RewriteDescriptor` on the owning worker —
/// forwarded indefinitely with no session row, no policy re-evaluation,
/// no `show security flow session` visibility, and no HA sync (a fail-open
/// revocation primitive: the operator's explicit `clear` did not stop
/// forwarding). Evicting here forces the next packet on the tuple to MISS
/// the cache and re-run full session lookup/creation + policy — fail-closed.
///
/// Ownership and precision mirror the reap path: the flow cache is
/// per-binding and worker-owned and this runs on the owning worker's
/// command dispatch, so the eviction is a same-thread mutation — no
/// cross-thread flush. Every binding is walked because a deleted session
/// does not carry the ingress ifindex the cache is keyed on; the session
/// table is keyed by the 5-tuple alone, so at most one live session —
/// hence at most one VALID descriptor — exists per key, and
/// `invalidate_slot` drops only a slot whose key AND ingress_ifindex both
/// match (on a non-owning binding it either no-ops or evicts a stale
/// prior-flow slot with the same tuple, never another live flow's entry).
/// `delete_synced_session_gen` fans out the forward AND reverse keys, so
/// both directions' slots are covered. The work is bounded by the
/// control-plane delete rate (one Vec push per delete inside
/// `handle_delete_synced`, one `invalidate_slot` walk per binding per
/// delete here) — zero per-packet cost: the hit path is untouched and
/// empty-delete ticks skip the call entirely.
fn invalidate_flow_cache_slots_for_deleted_sessions(
    bindings: &mut [BindingWorker],
    deleted_keys: &[crate::session::SessionKey],
) {
    for key in deleted_keys {
        for binding in bindings.iter_mut() {
            binding
                .flow
                .flow_cache
                .invalidate_slot(key, binding.ifindex);
        }
    }
}

/// #2428: count only the create-counted LOCAL-origin expired sessions for
/// the `session_expires` counter (which the Go control plane reads as
/// `GlobalCtrSessionsClosed`).
///
/// `session_creates` is bumped ONLY on the four local poll-descriptor install
/// paths — `ForwardFlow` / `ReverseFlow` / `LocalMiss` /
/// `MissingNeighborSeed`. Every other origin is synced-derived and never
/// create-counted:
///   - `SyncImport` / `SharedMaterialize` / `WorkerLocalImport` — installed
///     via the HA sync path (`upsert_synced_with_origin` /
///     `WorkerCommand::UpsertLocal`);
///   - `SharedPromote` — a re-tag of an already-synced (uncounted) entry by
///     `maybe_promote_synced_session` (`session_glue/promote.rs`); its
///     `promote_synced_with_origin` install does NOT touch `session_creates`.
///     `is_peer_synced()` returns FALSE for `SharedPromote`, so an earlier
///     `!is_peer_synced()` filter would have COUNTED a promote expiry that
///     was never create-counted — re-introducing the underflow on a node
///     that promotes synced sessions post-failover. `shared_ops.rs` already
///     groups `SharedPromote` with the peer-synced set for the wire-alias
///     contract; this counter is consistent with that.
///
/// Counting any non-create-counted origin's expiry inflates `session_expires`
/// past `session_creates`, wrapping the unsigned Go subtraction
/// `session_creates - session_expires` to ~1.8e19. We therefore match on the
/// EXACT complement of the create-counted set via an exhaustive `match` (NO
/// wildcard) so a future 9th `SessionOrigin` variant forces a compile-time
/// decision here rather than silently defaulting to "counted". The Go-side
/// `dataplane.CurrentSessions` saturating floor is the defense-in-depth
/// backstop.
fn count_local_session_expiries(
    origins: impl Iterator<Item = crate::session::SessionOrigin>,
) -> u64 {
    use crate::session::SessionOrigin;
    origins
        .filter(|o| match o {
            // The four create-counted local install paths: count their expiry.
            SessionOrigin::ForwardFlow
            | SessionOrigin::ReverseFlow
            | SessionOrigin::LocalMiss
            | SessionOrigin::MissingNeighborSeed => true,
            // #7770: a fabric PUNT SEED is installed without bumping
            // `session_creates` — the punting node deliberately keeps its
            // operator-visible create accounting unchanged, because the
            // AUTHORITATIVE session for a punted flow is the peer's. Its expiry
            // must therefore not be counted either, or `session_creates -
            // session_expires` wraps.
            SessionOrigin::FabricPuntSeed => false,
            // Synced-derived, never create-counted: must NOT be expire-counted.
            SessionOrigin::SyncImport
            | SessionOrigin::SharedMaterialize
            | SessionOrigin::SharedPromote
            | SessionOrigin::WorkerLocalImport => false,
        })
        .count() as u64
}

#[cfg(test)]
mod flow_cache_invalidation_tests {
    //! #3776: the GC reap path must invalidate the per-worker flow-cache
    //! slot(s) backing every session it reaps, so a packet that resumes on the
    //! same 5-tuple after the idle timeout MISSES the cache and re-runs full
    //! session lookup/creation + policy — instead of being forwarded via a
    //! stale `RewriteDescriptor` with no live session (stateful-firewall
    //! bypass) and a SNAT port that may now belong to a different flow
    //! (NAT-port reuse). These tests drive the production `reap_expired_sessions`
    //! helper the expiry loop calls; deleting its `invalidate_slot` loop turns
    //! `reaped_session_flow_cache_slot_is_invalidated` and
    //! `reaped_snat_descriptor_is_not_reused` RED.
    //!
    //! #6457: the control-plane delete path (operator `clear security flow
    //! session`, cluster-stale sweep, HA DeleteSynced — all funnelled through
    //! `WorkerCommand::DeleteSynced`) must invalidate the same slot(s) for the
    //! revoked key. Those tests drive the production
    //! `invalidate_flow_cache_slots_for_deleted_sessions` helper the worker
    //! loop calls with `WorkerCommandResults.deleted_synced_keys`; deleting
    //! its `invalidate_slot` loop turns `delete_synced_flow_cache_slot_is_
    //! invalidated` and `delete_synced_snat_descriptor_is_not_reused` RED.
    //! (The `handle_delete_synced` half — recording the key unconditionally —
    //! is pinned in `afxdp/session_glue/tests.rs`.)
    use super::*;
    use crate::nat::NatDecision;
    use crate::session::{
        ExpiredSession, SessionDecision, SessionKey, SessionMetadata, SessionOrigin,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU32, Ordering};

    const REAP_INGRESS_IF: i32 = 24;

    fn reap_rg_epochs() -> [AtomicU32; MAX_RG_EPOCHS] {
        std::array::from_fn(|_| AtomicU32::new(0))
    }

    fn reap_key(src_port: u16) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }
    }

    fn reap_metadata() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        }
    }

    fn reap_resolution() -> ForwardingResolution {
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        }
    }

    fn reap_decision(snat_port: Option<u16>) -> SessionDecision {
        SessionDecision {
            resolution: reap_resolution(),
            nat: NatDecision {
                rewrite_src: snat_port.map(|_| IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: snat_port,
                ..NatDecision::default()
            },
        }
    }

    fn insert_cache_entry(binding: &mut BindingWorker, key: &SessionKey, snat_port: Option<u16>) {
        insert_cache_entry_on_if(binding, key, snat_port, REAP_INGRESS_IF);
    }

    fn insert_cache_entry_on_if(
        binding: &mut BindingWorker,
        key: &SessionKey,
        snat_port: Option<u16>,
        ingress_ifindex: i32,
    ) {
        let decision = reap_decision(snat_port);
        binding.flow.flow_cache.insert(FlowCacheEntry {
            key: key.clone(),
            ingress_ifindex,
            logical_ingress_ifindex: ingress_ifindex,
            descriptor: RewriteDescriptor {
                dst_mac: [0; 6],
                src_mac: [0; 6],
                fabric_redirect: false,
                tx_vlan_id: 0,
                ether_type: 0x0800,
                rewrite_src_ip: decision.nat.rewrite_src,
                rewrite_dst_ip: None,
                rewrite_src_port: decision.nat.rewrite_src_port,
                rewrite_dst_port: None,
                ip_csum_delta: 0,
                l4_csum_delta: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                target_binding_index: None,
                input_filter_log: None,
                input_filter_counters: crate::filter::CachedFilterCounters::default(),
                tx_selection: CachedTxSelectionDescriptor::default(),
                nat64: false,
                nptv6: false,
                apply_nat_on_fabric: false,
            },
            decision,
            metadata: reap_metadata(),
            stamp: FlowCacheStamp {
                config_generation: 1,
                fib_generation: 1,
                owner_rg_id: 1,
                owner_rg_epoch: 0,
                owner_rg_lease_until: 0,
            },
            observed_bytes: 0,
            last_used_epoch: 0,
            neighbor_mac_epoch: 0,
            // #5147: no dynamic-neighbor dependency in this test entry.
            neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
        });
    }

    fn cache_hits(
        binding: &mut BindingWorker,
        key: &SessionKey,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
    ) -> bool {
        cache_hits_on_if(binding, key, rg_epochs, REAP_INGRESS_IF)
    }

    fn cache_hits_on_if(
        binding: &mut BindingWorker,
        key: &SessionKey,
        rg_epochs: &[AtomicU32; MAX_RG_EPOCHS],
        ingress_ifindex: i32,
    ) -> bool {
        binding
            .flow
            .flow_cache
            .lookup(
                key,
                FlowCacheLookup {
                    ingress_ifindex,
                    logical_ingress_ifindex: ingress_ifindex,
                    config_generation: 1,
                    fib_generation: 1,
                },
                0,
                rg_epochs,
            )
            .is_some()
    }

    fn expired(key: SessionKey, snat_port: Option<u16>) -> ExpiredSession {
        ExpiredSession {
            key,
            decision: reap_decision(snat_port),
            metadata: reap_metadata(),
            origin: SessionOrigin::ForwardFlow,
        }
    }

    // #3776 H1: a packet that resumes on a reaped flow's 5-tuple must MISS the
    // cache. Without the GC-path `invalidate_slot` the descriptor survives the
    // reap and the resumed packet is forwarded with no live session — the
    // stateful-firewall bypass. RED on revert (the entry survives, `cache_hits`
    // stays true after the reap).
    #[test]
    fn reaped_session_flow_cache_slot_is_invalidated() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(12345);
        insert_cache_entry(&mut binding, &key, None);
        assert!(
            cache_hits(&mut binding, &key, &rg_epochs),
            "precondition: an active flow's descriptor is cached and hits"
        );

        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired(key.clone(), None)],
            &forwarding,
            -1,
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert!(
            !cache_hits(&mut binding, &key, &rg_epochs),
            "#3776: a packet on a reaped flow's tuple must MISS the cache so it \
             re-runs full session lookup + policy (no sessionless forward)"
        );
        assert_eq!(
            binding.flow.flow_cache.entries.iter().flatten().count(),
            0,
            "#3776: the reaped flow's cache slot must be evicted"
        );
    }

    // #3776 H2: the SNAT-bearing descriptor of a reaped flow must not survive to
    // re-drive a translation whose port `release_source_nat_allocation` just
    // returned to the pool. RED on revert (the SNAT descriptor keeps hitting).
    #[test]
    fn reaped_snat_descriptor_is_not_reused() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(23456);
        insert_cache_entry(&mut binding, &key, Some(20001));
        assert!(cache_hits(&mut binding, &key, &rg_epochs));

        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired(key.clone(), Some(20001))],
            &forwarding,
            -1,
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert!(
            !cache_hits(&mut binding, &key, &rg_epochs),
            "#3776: a released-SNAT descriptor must not survive the reap and \
             re-SNAT to a port now owned by a different flow"
        );
    }

    // A flow that is NOT reaped this sweep must keep hitting the cache — the
    // #2220 keepalive fast path is preserved, the reap targets only the reaped
    // key, and there is no collateral invalidation.
    #[test]
    fn live_flow_survives_reap_of_a_different_flow() {
        let rg_epochs = reap_rg_epochs();
        let forwarding = ForwardingState::default();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let reaped = reap_key(30001);
        let live = reap_key(30002);
        insert_cache_entry(&mut binding, &reaped, None);
        insert_cache_entry(&mut binding, &live, None);
        assert!(cache_hits(&mut binding, &reaped, &rg_epochs));
        assert!(cache_hits(&mut binding, &live, &rg_epochs));

        reap_expired_sessions(
            std::slice::from_mut(&mut binding),
            &[expired(reaped.clone(), None)],
            &forwarding,
            -1,
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert!(
            !cache_hits(&mut binding, &reaped, &rg_epochs),
            "the reaped flow's slot is evicted"
        );
        assert!(
            cache_hits(&mut binding, &live, &rg_epochs),
            "a still-live flow's slot must survive the reap of a different flow \
             (no keepalive/hot-path regression, no collateral invalidation)"
        );
    }

    // #6457 H1: a control-plane session delete (operator `clear security flow
    // session`, cluster-stale sweep `BatchDeleteSessions`, HA DeleteSynced
    // propagation — all funnelled through `WorkerCommand::DeleteSynced`) must
    // evict the flow-cache slot backing the revoked session. None of those
    // paths bumps config/fib generation, RG epoch, or RG lease, so without
    // the explicit eviction the revoked-but-still-active 5-tuple keeps
    // HITTING its cached RewriteDescriptor and forwards with no live
    // session — the operator's revocation primitive silently defeated
    // (fail-open). Drives the production
    // `invalidate_flow_cache_slots_for_deleted_sessions` the worker loop
    // calls with `WorkerCommandResults.deleted_synced_keys`. RED on revert
    // (the entry survives, `cache_hits` stays true after the delete).
    #[test]
    fn delete_synced_flow_cache_slot_is_invalidated() {
        let rg_epochs = reap_rg_epochs();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(34567);
        insert_cache_entry(&mut binding, &key, None);
        assert!(
            cache_hits(&mut binding, &key, &rg_epochs),
            "precondition: an active flow's descriptor is cached and hits"
        );

        invalidate_flow_cache_slots_for_deleted_sessions(
            std::slice::from_mut(&mut binding),
            &[key.clone()],
        );

        assert!(
            !cache_hits(&mut binding, &key, &rg_epochs),
            "#6457: a packet on a revoked flow's tuple must MISS the cache so \
             it re-runs full session lookup + policy (no sessionless forward \
             under a stale cached permit)"
        );
        assert_eq!(
            binding.flow.flow_cache.entries.iter().flatten().count(),
            0,
            "#6457: the revoked flow's cache slot must be evicted"
        );
    }

    // #6457 H2: the SNAT-bearing descriptor of a revoked flow must not
    // survive the delete to re-drive a translation whose pool port
    // `handle_delete_synced` just returned to the allocator (the port may
    // already belong to a different flow). RED on revert (the SNAT
    // descriptor keeps hitting).
    #[test]
    fn delete_synced_snat_descriptor_is_not_reused() {
        let rg_epochs = reap_rg_epochs();
        let mut binding = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let key = reap_key(45678);
        insert_cache_entry(&mut binding, &key, Some(21000));
        assert!(cache_hits(&mut binding, &key, &rg_epochs));

        invalidate_flow_cache_slots_for_deleted_sessions(
            std::slice::from_mut(&mut binding),
            &[key.clone()],
        );

        assert!(
            !cache_hits(&mut binding, &key, &rg_epochs),
            "#6457: a revoked SNAT descriptor must not survive the delete and \
             re-SNAT to a port now owned by a different flow"
        );
    }

    // #6457: a deleted session carries no ingress ifindex, so the eviction
    // must walk EVERY binding of the worker — the flow may have been pinned
    // to any queue. Seed the revoked flow's descriptor in the SECOND
    // binding's cache (keyed on that binding's ingress ifindex) and assert
    // the walk reaches it; the first binding's still-live flow must survive
    // (no collateral invalidation of an unrelated key).
    #[test]
    fn delete_synced_invalidation_walks_every_binding() {
        let rg_epochs = reap_rg_epochs();
        let other_if = REAP_INGRESS_IF + 1;
        let mut binding_a = BindingWorker::new_for_mirror_test(0, 0, REAP_INGRESS_IF, 0);
        let mut binding_b = BindingWorker::new_for_mirror_test(1, 0, other_if, 0);
        let revoked = reap_key(56789);
        let live = reap_key(56790);
        insert_cache_entry_on_if(&mut binding_b, &revoked, None, other_if);
        insert_cache_entry(&mut binding_a, &live, None);
        assert!(cache_hits_on_if(&mut binding_b, &revoked, &rg_epochs, other_if));
        assert!(cache_hits(&mut binding_a, &live, &rg_epochs));

        let mut bindings = [binding_a, binding_b];
        invalidate_flow_cache_slots_for_deleted_sessions(&mut bindings, &[revoked.clone()]);
        let [binding_a, binding_b] = &mut bindings;

        assert!(
            !cache_hits_on_if(binding_b, &revoked, &rg_epochs, other_if),
            "#6457: the revoked flow's slot must be evicted even when it \
             lives on a non-first binding (the delete carries no ifindex)"
        );
        assert!(
            cache_hits(binding_a, &live, &rg_epochs),
            "#6457: an unrelated live flow must survive the delete of a \
             different flow (no collateral invalidation)"
        );
    }
}

#[cfg(test)]
mod expiry_count_tests {
    use super::count_local_session_expiries;
    use crate::session::SessionOrigin;

    #[test]
    fn local_origin_expiries_are_counted() {
        let origins = [
            SessionOrigin::ForwardFlow,
            SessionOrigin::ReverseFlow,
            SessionOrigin::LocalMiss,
            SessionOrigin::MissingNeighborSeed,
        ];
        assert_eq!(count_local_session_expiries(origins.into_iter()), 4);
    }

    #[test]
    fn synced_derived_expiries_are_not_counted() {
        // #2428: the standby (and any node) reaps synced-derived sessions it
        // never create-counted. None of these may bump session_expires, or
        // the Go-derived `session_creates - session_expires` underflows to a
        // wrapped u64. ALL FOUR synced-derived origins must be excluded —
        // including SharedPromote, whose is_peer_synced() returns false.
        let origins = [
            SessionOrigin::SyncImport,
            SessionOrigin::SharedMaterialize,
            SessionOrigin::WorkerLocalImport,
            SessionOrigin::SharedPromote,
        ];
        assert_eq!(
            count_local_session_expiries(origins.into_iter()),
            0,
            "synced-derived expiries must not bump session_expires (would \
             underflow the Current-sessions gauge)"
        );
    }

    #[test]
    fn shared_promote_expiry_is_not_counted() {
        // #2428 review fold: SharedPromote is a re-tag of an already-synced
        // (uncounted) entry — promote_synced_with_origin does NOT bump
        // session_creates. is_peer_synced() returns FALSE for it, so the
        // earlier `!is_peer_synced()` filter wrongly COUNTED a promote
        // expiry, re-introducing the underflow on a promoting node.
        // fail-on-revert: restoring `!o.is_peer_synced()` makes this case
        // return 1 instead of 0.
        assert_eq!(
            count_local_session_expiries([SessionOrigin::SharedPromote].into_iter()),
            0,
            "a SharedPromote expiry must NOT bump session_expires (never \
             create-counted)"
        );
    }

    #[test]
    fn mixed_batch_counts_only_create_counted_locals() {
        let origins = [
            SessionOrigin::ForwardFlow,       // local: +1
            SessionOrigin::SyncImport,        // synced: 0
            SessionOrigin::ReverseFlow,       // local: +1
            SessionOrigin::SharedMaterialize, // synced: 0
            SessionOrigin::WorkerLocalImport, // synced: 0
            SessionOrigin::SharedPromote,     // synced: 0
        ];
        assert_eq!(count_local_session_expiries(origins.into_iter()), 2);
    }

    #[test]
    fn taxonomy_is_eight_variants() {
        // #2428: pin the SessionOrigin taxonomy at 8. The exhaustive match in
        // count_local_session_expiries (no wildcard) already forces a
        // compile-time decision on a new variant; this enumerates every
        // variant and asserts it classifies exactly once into local (4) or
        // synced-derived (4). A 9th variant breaks BOTH the match (compile
        // error) and this count (8 -> 9) — a loud double signal.
        let all = [
            SessionOrigin::ForwardFlow,
            SessionOrigin::ReverseFlow,
            SessionOrigin::LocalMiss,
            SessionOrigin::MissingNeighborSeed,
            SessionOrigin::SyncImport,
            SessionOrigin::SharedMaterialize,
            SessionOrigin::SharedPromote,
            SessionOrigin::WorkerLocalImport,
        ];
        assert_eq!(all.len(), 8, "SessionOrigin taxonomy is 8 variants");
        // Exactly the four create-counted locals are counted.
        assert_eq!(count_local_session_expiries(all.into_iter()), 4);
    }
}

#[cfg(test)]
mod snapshot_refresh_ordering_tests {
    use super::*;

    /// A published `(generation, forwarding)` fixture. Holding every `Arc`
    /// alive for the whole test is load-bearing: `Arc::ptr_eq` is the only way
    /// to map an observed forwarding allocation back to the generation it was
    /// published with, and a dropped allocation could be recycled by the next
    /// `Arc::new` and fool it.
    struct PublishedGenerations {
        views: Vec<(u64, Arc<ForwardingState>)>,
    }

    impl PublishedGenerations {
        fn new() -> Self {
            Self { views: Vec::new() }
        }

        /// Mint a fresh forwarding allocation stamped with `generation`, and
        /// return the `RuntimeView` the coordinator would publish for it.
        fn mint(&mut self, generation: u64) -> Arc<RuntimeView> {
            let forwarding = Arc::new(ForwardingState::default());
            self.views.push((generation, forwarding.clone()));
            Arc::new(RuntimeView::new(  // runtime-view-canary: test-local
                ValidationState {
                    snapshot_installed: true,
                    config_generation: generation,
                    fib_generation: generation as u32,
                },
                forwarding,
            ))
        }

        /// The generation `forwarding` was published with.
        fn generation_of(&self, forwarding: &Arc<ForwardingState>) -> u64 {
            self.views
                .iter()
                .find(|(_, published)| Arc::ptr_eq(published, forwarding))
                .map(|(generation, _)| *generation)
                .expect("every forwarding allocation under test is minted here")
        }
    }

    /// #6592 pairing regression (deterministic fail-on-revert), CONSUMER half.
    ///
    /// A worker's per-tick refresh must take validation AND forwarding from ONE
    /// `ArcSwap` load, so the pair it ends up holding is always the pair the
    /// coordinator published. Two separate loads — in EITHER order — let a
    /// coordinator publish land between them and tear the pair:
    /// - validation loaded first → `(old validation, new forwarding)`. A packet
    ///   stamped at the OLD generation passes `classify_metadata` and is then
    ///   forwarded under the NEW tables. (#6291.)
    /// - forwarding loaded first → `(new validation, old forwarding)`. Once Go
    ///   writes the new generation to `userspace_ctrl` the shim stamps NEW;
    ///   those packets pass `classify_metadata` against the new validation and
    ///   are forwarded under the STALE tables — a withdrawn route still
    ///   resolves, a new deny is not applied. (#6592.) This is the orientation
    ///   #6291's reorder left behind, and it is the COMMON one.
    ///
    /// The test drives `refresh_runtime_view` with a coordinator publish
    /// injected through the `between` seam — deterministically reproducing the
    /// ≤1-tick interleaving with NO thread race — and asserts the returned pair
    /// is COHERENT: the observed validation is the generation the observed
    /// forwarding was published with. That single assertion catches BOTH
    /// orientations, because both produce a mismatch. Splitting
    /// `refresh_runtime_view` back into two `ArcSwap` loads in either order
    /// turns it RED.
    ///
    /// Note what is deliberately NOT asserted: that the worker observes the
    /// NEW generation. Observing the OLD view is a legitimate, SAFE outcome —
    /// a worker that has not refreshed drops new-stamped packets, the intended
    /// fail-closed behaviour. #6592 closes INCOHERENT pairs, not stale coherent
    /// ones. Case 3 covers convergence separately.
    #[test]
    fn snapshot_refresh_runtime_view_pair_is_atomic_6592() {
        let mut published = PublishedGenerations::new();

        // Drive the REAL publish/read split: a coordinator-side channel and a
        // worker-side read-only handle. The worker literally cannot publish
        // here — `RuntimeViewReader` has no store — so the test exercises the
        // same capability boundary production does.
        let channel = RuntimeViewChannel::default();
        channel.publish(published.mint(1));
        let shared_runtime = channel.reader();

        // Assert the returned pair is internally coherent, and report which
        // torn orientation a failure represents so a revert names its own bug.
        let assert_coherent = |published: &PublishedGenerations,
                               cached: &Arc<ForwardingState>,
                               new_forwarding_opt: &Option<Arc<ForwardingState>>,
                               observed: ValidationState,
                               case: &str| {
            // The pair the worker actually ends the tick holding: the adopted
            // Arc if forwarding rotated, otherwise its unchanged cached one.
            let effective = new_forwarding_opt.as_ref().unwrap_or(cached);
            let forwarding_generation = published.generation_of(effective);
            let orientation = if observed.config_generation > forwarding_generation {
                "(new validation, old forwarding) — the #6592 mirror: \
                 new-stamped packets classify Valid and forward under STALE tables"
            } else {
                "(old validation, new forwarding) — the #6291 orientation: \
                 old-stamped packets classify Valid and forward under NEW tables"
            };
            assert_eq!(
                observed.config_generation, forwarding_generation,
                "#6592 [{case}]: worker holds a TORN pair {orientation}. \
                 Both halves must come from ONE view load",
            );
        };

        // --- Case 1: the worker is UP TO DATE and a publish lands mid-refresh.
        // Its cached forwarding is the currently-published one, so with a
        // single load nothing rotates (#1188 short-circuit) and it keeps the
        // whole old pair — coherent, and safe.
        let cached = shared_runtime.load().forwarding().clone();
        let view2 = published.mint(2);
        let (new_forwarding_opt, observed) =
            refresh_runtime_view(&cached, &shared_runtime, |_| {
                channel.publish(view2);
            });
        assert_coherent(
            &published,
            &cached,
            &new_forwarding_opt,
            observed,
            "publish during refresh, worker up to date",
        );

        // --- Case 2: the worker is BEHIND (a publish already landed before its
        // load) and ANOTHER publish lands mid-refresh. Now the refresh really
        // does adopt a new forwarding Arc, so the coherence assert above is not
        // satisfiable by simply never adopting anything.
        let view3 = published.mint(3);
        let (new_forwarding_opt, observed) =
            refresh_runtime_view(&cached, &shared_runtime, |_| {
                channel.publish(view3);
            });
        assert!(
            new_forwarding_opt.is_some(),
            "a worker behind by a generation must adopt the published \
             forwarding — otherwise the coherence assert is vacuous",
        );
        assert_coherent(
            &published,
            &cached,
            &new_forwarding_opt,
            observed,
            "publish during refresh, worker behind",
        );

        // --- Case 3: with no concurrent publish the worker CONVERGES on the
        // latest published pair. This is what makes cases 1 and 2 non-vacuous:
        // the injected publishes were real and reachable, they just were not
        // observable by a load that had already happened.
        let (new_forwarding_opt, observed) =
            refresh_runtime_view(&cached, &shared_runtime, |_| {});
        let adopted = new_forwarding_opt
            .clone()
            .expect("the worker must adopt the latest published forwarding");
        assert_coherent(
            &published,
            &cached,
            &new_forwarding_opt,
            observed,
            "quiescent refresh",
        );
        assert_eq!(
            observed.config_generation, 3,
            "a quiescent refresh must converge on the newest published pair",
        );
        assert!(
            Arc::ptr_eq(&adopted, shared_runtime.load().forwarding()),
            "the adopted forwarding must be the published allocation",
        );

        // --- Case 4 (#1188): a VALIDATION-ONLY publish — what
        // `Coordinator::republish_runtime_validation` does for a FIB bump —
        // advances the stamps while REUSING the forwarding Arc, so the worker
        // sees the new validation with no rotation and skips its expensive
        // forwarding-rotation branch. The pair stays coherent because it is
        // still one view.
        let unrotated = shared_runtime.load().forwarding().clone();
        channel.publish(Arc::new(RuntimeView::new(  // runtime-view-canary: test-local
            ValidationState {
                snapshot_installed: true,
                config_generation: 3,
                fib_generation: 99,
            },
            unrotated.clone(),
        )));
        let (new_forwarding_opt, observed) =
            refresh_runtime_view(&adopted, &shared_runtime, |_| {});
        assert!(
            new_forwarding_opt.is_none(),
            "#1188: a validation-only publish must NOT rotate the worker's \
             forwarding Arc — rotating it drags every worker through the \
             expensive rotation branch for a change that touched no table",
        );
        assert_eq!(
            observed.fib_generation, 99,
            "the validation-only publish must still be observed",
        );
        assert_coherent(
            &published,
            &adopted,
            &new_forwarding_opt,
            observed,
            "validation-only publish",
        );
    }
}

#[cfg(test)]
mod gc_reap_source_nat_release_tests_6901 {
    //! #6901: the GC reap's `release_source_nat_allocation_for_worker` call was
    //! UNBOUND — deleting it left the whole crate green (measured: 4670
    //! collected, 0 failed, both with and without the call).
    //!
    //! `reap_expired_sessions` is the ordinary inactivity-timeout teardown, the
    //! path that frees a source-NAT pool port for the overwhelming majority of
    //! sessions — they age out rather than being explicitly deleted. Without the
    //! call, every reaped translated session leaks a pool port until
    //! `AllocatorExhausted`, and nothing in the suite noticed.
    //!
    //! TWO cells, because "the reap calls release" and "the reap releases the
    //! port THIS session holds" are different claims and only the first is
    //! bound by a count going to zero. A release that freed the wrong pool
    //! would satisfy a single-pool fixture.
    use super::*;
    use crate::nat::NatDecision;
    use crate::session::{
        ExpiredSession, SessionDecision, SessionKey, SessionMetadata, SessionOrigin,
    };
    use std::net::{IpAddr, Ipv4Addr};

    const POOL_A: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 8);
    const POOL_B: Ipv4Addr = Ipv4Addr::new(172, 16, 90, 9);

    fn rule_snapshot(name: &str, from: &str, pool_addr: Ipv4Addr) -> crate::SourceNATRuleSnapshot {
        crate::SourceNATRuleSnapshot {
            name: name.to_string(),
            from_zone: from.to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: name.to_string(),
            pool_addresses: vec![format!("{pool_addr}/32")],
            port_low: 1024,
            port_high: 65535,
            ..crate::SourceNATRuleSnapshot::default()
        }
    }

    fn key_for(src_port: u16) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            src_port,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }
    }

    fn nat_for(pool_addr: Ipv4Addr, port: u16) -> NatDecision {
        NatDecision {
            rewrite_src: Some(IpAddr::V4(pool_addr)),
            rewrite_src_port: Some(port),
            ..NatDecision::default()
        }
    }

    fn metadata() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        }
    }

    fn expired_for(src_port: u16, pool_addr: Ipv4Addr, snat_port: u16) -> ExpiredSession {
        ExpiredSession {
            key: key_for(src_port),
            decision: SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 12,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                    neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                    src_mac: Some([6, 7, 8, 9, 10, 11]),
                    tx_vlan_id: 0,
                },
                nat: nat_for(pool_addr, snat_port),
            },
            metadata: metadata(),
            origin: SessionOrigin::ForwardFlow,
        }
    }

    fn used(forwarding: &ForwardingState, pool: &str) -> u64 {
        crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)
            .into_iter()
            .find(|s| s.pool_name == pool)
            .unwrap_or_else(|| panic!("no pool status for {pool}"))
            .used_ports
    }

    /// The reap returns the pool port. Fail-on-revert: delete the
    /// `release_source_nat_allocation_for_worker` call in `reap_expired_sessions`
    /// and this goes RED — before #6901 that deletion left the crate green.
    #[test]
    fn gc_reap_releases_the_source_nat_pool_port_6901() {
        let mut forwarding = ForwardingState::default();
        forwarding.source_nat_rules =
            crate::nat::parse_source_nat_rules(&[rule_snapshot("pool-a", "lan", POOL_A)]);

        crate::nat::reserve_synced_source_nat_allocation(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &key_for(1111),
            nat_for(POOL_A, 40000),
            false,
            None,
            0,
        );
        assert_eq!(
            used(&forwarding, "pool-a"),
            1,
            "precondition: the translated flow must hold one pool port, or the \
             assertion below passes against a pool that was never allocated from",
        );

        reap_expired_sessions(
            &mut [],
            &[expired_for(1111, POOL_A, 40000)],
            &forwarding,
            -1,
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert_eq!(
            used(&forwarding, "pool-a"),
            0,
            "the GC reap must return the pool port. Without this the ordinary \
             inactivity teardown leaks one port per reaped translated session \
             until AllocatorExhausted (#6901)",
        );
    }

    /// It releases the port THIS session holds, not merely some port. A single
    /// pool cannot tell those apart: a release that freed the wrong allocator
    /// would still drive one count to zero.
    #[test]
    fn gc_reap_releases_only_the_reaped_flows_pool_6901() {
        let mut forwarding = ForwardingState::default();
        forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
            rule_snapshot("pool-a", "lan", POOL_A),
            rule_snapshot("pool-b", "dmz", POOL_B),
        ]);

        for (key_port, pool, snat_port) in [(1111u16, POOL_A, 40000u16), (2222, POOL_B, 40001)] {
            crate::nat::reserve_synced_source_nat_allocation(
                &forwarding.iface_nat_allocators,
                &forwarding.source_nat_rules,
                &key_for(key_port),
                nat_for(pool, snat_port),
                false,
                None,
                0,
            );
        }
        assert_eq!(
            (used(&forwarding, "pool-a"), used(&forwarding, "pool-b")),
            (1, 1),
            "precondition: both pools hold one port",
        );

        // Reap ONLY the pool-a flow.
        reap_expired_sessions(
            &mut [],
            &[expired_for(1111, POOL_A, 40000)],
            &forwarding,
            -1,
            -1,
            -1,
            1_000_000_000,
            0,
        );

        assert_eq!(
            used(&forwarding, "pool-a"),
            0,
            "the reaped flow's own pool must be released",
        );
        assert_eq!(
            used(&forwarding, "pool-b"),
            1,
            "the OTHER pool must be untouched — a release that freed by count \
             rather than by the reaped flow's own (pool, port) would free a \
             port another live session is still forwarding through",
        );
    }
}

#[cfg(test)]
mod gc_reap_nat64_release_tests_7740 {
    //! #7740: the GC reap's `release_nat64_allocation_for_worker` call is
    //! UNBOUND — the sibling of the source-NAT release #6901 bound, two lines
    //! below it in the same loop. Measured: neutering it leaves the crate green
    //! at the full collection.
    //!
    //! There ARE NAT64 release tests (`nat64_tests.rs`), but they call
    //! `release_nat64_allocation` DIRECTLY. The function is bound; its reap
    //! call site is not — which is the same shape as #6901 in a different
    //! allocator, and the reason "the function has tests" is not an answer to
    //! "the call site is unbound".
    //!
    //! TWO cells, mirroring #6901: that the reap releases at all, and that it
    //! releases the allocation THIS session holds. The second is what a
    //! single-flow fixture cannot see.
    use super::*;
    use crate::nat64::Nat64State;
    use crate::session::{ExpiredSession, SessionDecision, SessionKey, SessionOrigin};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const DST_V4: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

    fn prefix() -> crate::NAT64RuleSnapshot {
        crate::NAT64RuleSnapshot {
            name: "nat64-single".to_string(),
            prefix: "64:ff9b::/96".to_string(),
            // One address, so only the translated PORT can disambiguate two
            // flows — which is what makes the second cell meaningful.
            pool_addresses: vec!["198.51.100.1".to_string()],
            no_v6_frag_header: false,
            ..Default::default()
        }
    }

    fn client(n: u16) -> Ipv6Addr {
        format!("2001:db8::{n}").parse().unwrap()
    }

    fn key_for(c: Ipv6Addr, src_port: u16) -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(c),
            dst_ip: IpAddr::V6("64:ff9b::0808:0808".parse().unwrap()),
            src_port,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        }
    }

    fn metadata() -> crate::session::SessionMetadata {
        crate::session::SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        }
    }

    fn expired(key: SessionKey, nat: crate::nat::NatDecision) -> ExpiredSession {
        ExpiredSession {
            key,
            decision: SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 12,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
                    neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
                    src_mac: Some([6, 7, 8, 9, 10, 11]),
                    tx_vlan_id: 0,
                },
                nat,
            },
            metadata: metadata(),
            origin: SessionOrigin::ForwardFlow,
        }
    }

    fn reap(forwarding: &ForwardingState, entries: &[ExpiredSession]) {
        reap_expired_sessions(&mut [], entries, forwarding, -1, -1, -1, 1_000_000_000, 0);
    }

    /// The reap returns the NAT64 translated port. The observable is the one
    /// `nat64_4381_release_untracks_flow` already uses: while the flow is live
    /// a re-allocation is IDEMPOTENT, and after release a fresh port is issued.
    ///
    /// Fail-on-revert: neuter `release_nat64_allocation_for_worker` in
    /// `reap_expired_sessions` and this goes RED — before #7740 that left the
    /// crate green.
    #[test]
    fn gc_reap_releases_the_nat64_allocation_7740() {
        let mut forwarding = ForwardingState::default();
        forwarding.nat64 = Nat64State::from_snapshots(&[prefix()]);
        let c = client(1);

        let (snat, port) = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c, DST_V4, 5000, 443, 1)
            .expect("allocate");
        assert_eq!(
            forwarding
                .nat64
                .allocate_source(0, PROTO_TCP, c, DST_V4, 5000, 443, 1)
                .expect("re-allocate"),
            (snat, port),
            "precondition: while live the mapping is idempotent, so a DIFFERENT \
             port after the reap is the release and nothing else",
        );

        reap(
            &forwarding,
            &[expired(
                key_for(c, 5000),
                Nat64State::forward_decision(snat, DST_V4, port),
            )],
        );

        let (snat2, port2) = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c, DST_V4, 5000, 443, 3)
            .expect("post-reap allocate");
        assert_eq!(snat2, snat, "same one-address pool");
        assert_ne!(
            port2, port,
            "the GC reap must release the NAT64 translated port. An idempotent \
             re-allocation means the flow is still live — the reaped session \
             leaked its port (#7740)",
        );
    }

    /// It releases the allocation THIS session holds. With a one-address pool
    /// only the port disambiguates, so a release that freed by count — or freed
    /// the wrong flow — would still let the first cell pass.
    #[test]
    fn gc_reap_releases_only_the_reaped_nat64_flow_7740() {
        let mut forwarding = ForwardingState::default();
        forwarding.nat64 = Nat64State::from_snapshots(&[prefix()]);
        let (c1, c2) = (client(1), client(2));

        let (snat1, port1) = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c1, DST_V4, 5000, 443, 1)
            .expect("allocate c1");
        let (snat2, port2) = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c2, DST_V4, 5001, 443, 1)
            .expect("allocate c2");
        assert_ne!(
            port1, port2,
            "precondition: two live flows hold two distinct translated ports",
        );

        // Reap ONLY the first flow.
        reap(
            &forwarding,
            &[expired(
                key_for(c1, 5000),
                Nat64State::forward_decision(snat1, DST_V4, port1),
            )],
        );

        let fresh1 = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c1, DST_V4, 5000, 443, 3)
            .expect("post-reap allocate c1");
        assert_ne!(
            fresh1.1, port1,
            "the reaped flow's own allocation must be released",
        );

        let still2 = forwarding
            .nat64
            .allocate_source(0, PROTO_TCP, c2, DST_V4, 5001, 443, 3)
            .expect("allocate c2 again");
        assert_eq!(
            still2,
            (snat2, port2),
            "the OTHER flow must still be live and idempotent — a release keyed \
             on anything but the reaped flow's own (client, port) would free a \
             translation another live session is still forwarding through",
        );
    }
}
