# userspace-dp/src/afxdp/worker/

The per-worker hot path. One `BindingWorker` per RSS queue, owns
its AF_XDP socket + UMEM + RX/TX/fill/completion rings + per-worker
state. The `worker_loop` fn (defined in `loop_body/mod.rs`,
re-exported from `worker/mod.rs`) calls `poll_binding` once per
binding per tick.

`worker_loop` was extracted out of `worker/mod.rs` into `loop_body/`
in #1326 Phase 1 (PR #1569) when `worker/mod.rs` crossed the 2000-LOC
modularity gate. #1776 (Phase 2, narrowed v3.1 scope) carved the two
cold extractions out of the fn: `loop_body/setup.rs` (one-shot setup,
returns the loop's initial `WorkerLoopSetup` state) and
`loop_body/debug_report.rs` (the cfg(debug-log) verbose report /
stall dump + `DbgCounters`, feature-gated at the `mod` declaration so
release builds compile none of it). #13075 (D4-12) split selected
per-tick control work from this file into deliberate
`#[inline(never)]` calls: `housekeeping::run_session_housekeeping`,
`pptp_drain::run_pptp_control_drain`, `ct_slice::run_ct_slice`,
`delta_recovery::run_delta_recovery`, and
`export_slice::run_export_slice`. The loop in `loop_body/mod.rs`
retains their call order, ArcSwap/config refreshes
(`load_arc_if_changed`), worker-command drain, binding poll sweep,
and periodic `BindingLiveState` publication. The same split moved
snapshot-rotation helpers to `reconcile.rs` and GC/delete helpers
to `gc_teardown.rs`; see the file table. The narrower #1776 codegen
constraint still applies specifically to `load_arc_if_changed`: do
not place a new `#[inline(never)]` boundary in front of that hot
per-tick refresh path. The paired-runtime refresh,
`refresh_runtime_view` (#6291/#6592) remains `#[inline]`; its inlined
`between` seam carries the #15151 IPsec-inner pending-work drain.

#5189 (A1-b8-F5) narrowed what "always-on" covers at the ~1 s report
tick. #1776 gated only the `eprintln!` and left the `binding_summary`
diagnostics BUILD inline and ungated, so a release build paid, per
worker per second, a heap `String` plus every `write!` that grows it,
one `statistics_v2()` (`XDP_STATISTICS` `getsockopt`) per binding, and
one `SO_ERROR` `getsockopt` per binding — for a value whose only
consumer was compiled out. That build is now
`debug_report::build_binding_summary`, called from a `#[cfg(feature =
"debug-log")]` binding, so release builds compile none of it. The
report tick's ALWAYS-ON half is unchanged and is what operators
actually read: the `BindingLiveState` publish/reset loop, which stores
the ring-pressure counters, its own `rx_fill_ring_empty_descs` sample,
`outstanding_tx` and `umem_inflight_frames` as fixed scalar atomics
(#802/#878). The report cadence (`dbg_last_report_ns`) is also
unchanged — the tick still fires every ~1 s in release, it just does
the publish and nothing else.

`BindingWorker` was decomposed into sub-structs in #959 (Phases 1–11).
Each phase extracted one cluster of fields into a dedicated
sub-struct so the parent struct stays cache-line-friendly and so
each cluster has a clear ownership boundary.

## Idle regulation

A tick that did no work increments `idle_iters` and then backs off according
to `poll_mode`. `BusyPoll` spins for `IDLE_SPIN_ITERS` (256) iterations and
then sleeps `IDLE_SLEEP_US` (1 us). `Interrupt` spins for the same window —
firewall-local TCP is ACK-latency-sensitive, so blocking on the first empty
poll collapses cwnd — and then blocks in `libc::poll` on every binding's
AF_XDP socket fd with an `INTERRUPT_POLL_TIMEOUT_MS` (1 ms) timeout. When the
worker has no bindings there is no fd to block on, so it sleeps the same 1 ms
instead.

That blocking `poll` is the ONLY backoff `Interrupt` mode has past the spin
window, which is why #6431 made its return a checked value rather than a
discarded one. `loop_body/idle_poll::classify` splits the return into three
cases:

| return | classification | caller |
|--------|----------------|--------|
| `0` (timeout), or `> 0` with `POLLIN` set on some fd | `Waited` | resume — the wait waited |
| `-1` with `EINTR` | `Interrupted` | retry; the next pass re-enters the poll, so this costs one work scan and no sleep |
| `-1` with any other errno, or `> 0` with only `POLLNVAL`/`POLLERR`/`POLLHUP` | `Degraded` | substitute a `INTERRUPT_POLL_TIMEOUT_MS` sleep |

The `Degraded` cases are the ones that matter: both return IMMEDIATELY and
keep doing so, so without a substituted sleep the 1 ms floor disappears
entirely and the idle path becomes a hot spin on a pinned core. Measured with
the production 1 ms timeout: a healthy idle poll yields ~950 loops/s, the same
loop over a closed fd ~2.96M loops/s — a ~3120x amplification held for as long
as the condition lasts. `EINTR` is deliberately NOT a `Degraded` case: the
helper installs a `ctrlc` handler (`server/lifecycle.rs`) and `poll(2)` is one
of the calls `SA_RESTART` never restarts (signal(7)), so signal-interrupted
waits are ordinary and must not each buy a sleep. The degraded log is latched
to one line per worker, because the condition that produces it repeats every
pass. RX is unaffected either way — the rings are swept on every loop pass;
`poll` only regulates how long an idle worker waits between sweeps.

## Files

| File | Purpose |
|------|---------|
| `bind_meta.rs` | `WorkerBindMeta` (#959 Phase 8) — bind time, copy/ZC mode, and binding identity. |
| `bpf_maps.rs` | `WorkerBpfMaps` (#959 Phase 5) — the four BPF map FDs opened once per worker. |
| `cos/interface_row.rs` | #1349 per-interface CoS status-row accumulator. |
| `cos/mod.rs` | Per-worker CoS runtime helpers and shared-exact threshold; declares the CoS status submodules. |
| `cos/queue_row.rs` | #1349 per-queue CoS status-row accumulator. |
| `cos/status.rs` | #1349 worker-side CoS status snapshot orchestrator. |
| `cos_state.rs` | `WorkerCos` (#959 Phase 3) — per-binding CoS-engine state. |
| `flow_cache_state.rs` | `WorkerFlowCacheState` (#959 Phase 9) — per-worker flow cache and keepalive state. |
| `launch.rs` | #6241 typed worker-launch bundles (`WorkerLaunchPlan`, `WorkerSharedDataplane`, `WorkerControlChannels`, `WorkerCoSState`, `WorkerPublishedTelemetry`, `WorkerNeighbors`, `WorkerSharedSessions`) replacing the 38-parameter positional `worker_loop` protocol. |
| `lifecycle.rs` | `poll_binding` — the per-binding RX/TX orchestrator. |
| `loop_body/ct_slice.rs` | #13075 per-tick conntrack refresh and fabric/WG drains (`run_ct_slice`, `#[inline(never)]`); also the pending-neighbor retry timer. The #16217/#16223 shared-evidence pass advances a persistent worker-table cursor by at most `CT_EVIDENCE_CHUNK` (2048) slots per ct-slice. Stage/count reads use the maintained forward-wire `entry.key` alias directory plus direct derived-key reads; each map-lock hold visits at most 128 candidates/rows, and each `run_ct_slice` invocation charges at most 16,384 lookup/fold operations. Pending stage/count traversal retains its cursors and delays worker-cursor advancement until all requested folds complete; no partial output is emitted. Alias publication/removal/displacement/restamp keep the index paired with its map. The slab-based cadence is a worker-slot baseline; high alias fan-out can add paced slices (see #18662 and `docs/log/18662.md`). |
| `loop_body/delta_recovery.rs` | #13075 per-tick delta-loss recovery and stale-session sweeps (`run_delta_recovery`, `#[inline(never)]`). |
| `loop_body/debug_report.rs` | #1776 cfg(debug-log)-only counters, per-second report, and stall dump; compiled out of release builds. |
| `loop_body/export_slice.rs` | #13075 per-tick CommandExport slice and steady-state delta drain (`run_export_slice`, `#[inline(never)]`). |
| `loop_body/gc_teardown.rs` | #13075 session-expiry/GC and control-plane delete teardown helpers, re-exported for worker call sites. |
| `loop_body/housekeeping.rs` | #13075 per-tick session expiry/GC housekeeping and close-delta drain (`run_session_housekeeping`, `#[inline(never)]`); #19026 parked-first retries, bounded ring drain, ring-before-overflow order. |
| `loop_body/close_barrier.rs` | #19026 bounded close-permit barrier: one RX bound per run of held ticks, park at the bound into a side slot, head-blocked bit, rate-limited park log. |
| `loop_body/idle_poll.rs` | #6431 `#[inline]` classification of Interrupt-mode idle `poll(2)` returns and one-shot fault summary. |
| `loop_body/mod.rs` | `worker_loop` steady-state orchestrator; retains per-tick call ordering while selected control slices are `#[inline(never)]` calls into sibling modules. |
| `loop_body/pptp_drain.rs` | #13075 per-tick PPTP control-inbox drain (`run_pptp_control_drain`, `#[inline(never)]`). |
| `loop_body/reconcile.rs` | #13075 forwarding-snapshot rotation reconciliation and the `#[inline]` `refresh_runtime_view` seam carrying the #15151 IPsec-inner drain. |
| `loop_body/screen_status.rs` | Publishes cumulative worker ScreenState status through a live binding on the report tick. |
| `loop_body/setup.rs` | #1776 one-shot worker setup: thread pinning, TSC calibration, binding construction, and BPF-map-FD cache. |
| `loop_body/slice_pacing.rs` | #13075 shared pacing limits for the extracted slices: the #9856 CommandExport scan budget, emit cap and deadline (`EXPORT_SLICE_*`), and the #333/#5287 conntrack-refresh window, slice interval and slice budget (`CT_REFRESH_WINDOW_NS`, `CT_SLICE_INTERVAL_NS`, `CT_REFRESH_SLICE_BUDGET`). Two const asserts fail the build if the export emit cap exceeds the scan budget, or if the default session cap or the windows would break the #18655 shared-evidence latency bound described under `loop_body/ct_slice.rs`. |
| `mod.rs` | `BindingWorker` and shared-binding helpers; re-exports `worker_loop` and the worker-launch bundle types. |
| `scratch.rs` | `WorkerScratch` (#959 Phase 2) — pre-allocated per-poll reusable buffers. |
| `synced_entry.rs` | `SyncedSessionEntry` — HA/shared-map session state and its mapping to an install request (#9412). |
| `telemetry.rs` | `WorkerTelemetry` (#959 Phase 1) — worker-local debug counters. |
| `timers.rs` | `WorkerTimers` (#959 Phase 6) — per-binding wake and heartbeat pacing. |
| `tx_counters.rs` | `WorkerTxCounters` (#959 Phase 4) — per-binding TX-disposition counters. |
| `tx_pipeline.rs` | `WorkerTxPipeline` (#959 Phases 7 and 10) — TX buffers and outstanding-TX state. |
| `xsk_rings.rs` | `WorkerXskRings` (#959 Phase 11) — the kernel device, RX, and TX rings. |

## Where it sits

- Top of the dataplane stack. Spawned by `coordinator/supervisor.rs`.
- Reads/writes to all the AF_XDP sub-modules (`umem/`, `tx/`,
  `frame/`, `cos/`, `forwarding/`, `session_glue/`).
- After #959, fields are accessed via the sub-struct prefix
  (`binding.cos.cos_X`, `binding.scratch.scratch_X`, etc.). The
  per-phase top-of-file comments name which field cluster moved.

## Notable invariants

- **Housekeeping never starves RX (#19026).** A Close delta that cannot
  take its tuple install permits is a teardown barrier. `run_session_housekeeping`
  retries it before command/control work and before `poll_binding`, which
  keeps the #10419 teardown-before-poll order. `loop_body/close_barrier.rs`
  bounds that barrier:
  - **One RX bound per run.** A run is the consecutive ticks that skipped RX
    for blocked Closes, whichever Closes they were. Inside
    `CLOSE_PERMIT_BARRIER_NS` (1 ms, the idle path's
    `INTERRUPT_POLL_TIMEOUT_MS`) of the run's start the tick skips RX; only a
    tick that polls RX ends the run. A Close that blocks after an RX tick
    gets its own window again.
  - **At the bound the blocked Close is parked** out of the FIFO into a side
    slot, and the drain continues in the same tick: the deltas behind it (the
    other Closes, HA sync, RT_FLOW, the RPC mirror) retire before RX polls, up
    to the pass's parking budget (below). The parked Close is retried on every
    tick, before the drains and again after them. Once its permit frees it
    retires on the first tick whose ring has room after the drain. Three rules
    keep the parked slot as good as the ring it left (Codex review of
    bbe57884f2):
    - **Cancellation reaches it.** `SessionTable::cancel_pending_close` (the
      pressure-shed retry's reply-evidence protection) searches the ring.
      For a Close it cannot find there, it records a cancellation, which the
      parked retry applies before retrying anything. Without that rule a
      reply-protected flow was torn down by its parked Close.
    - **A retry needs ring room.** A retry whose flush loses the permit race
      is requeued by that flush, and `requeue_deltas_front` drops what does
      not fit. So a parked Close is retried only while the ring has a free
      slot. The retry also runs AFTER the drains, which made room. Without
      that second retry, a ring that is full again at every housekeeping
      entry postponed a free parked Close without bound (Codex review of
      af0ea8415c).
    - **The ring is drained once more after the overflow suffix.** An
      overflow chunk's flush can lose its permit race and requeue the chunk
      into the ring, so a successful purge does not mean the Close retired.
      Master ran a final ring drain after the suffix; so does this, through
      the same bounded barrier.
  - **One parking pass is bounded in work, not only in ticks** (Codex review
    of af0ea8415c). The 1 ms bound limits skipped ticks. Each park, however,
    used to re-drain and requeue the next 256-delta batch, so 4,096 distinct
    blocked Closes cost 1,015,680 delta drains (about 36 ms, optimized) in
    the one pass that parked them. Master stopped at the first blocked head.
    Now:
    - a newly exposed head that is itself a blocked Close is marked at once,
      so it costs one permit try instead of a re-drain;
    - each pass spends at most `CLOSE_PARK_PASS_BUDGET` (one ring,
      `MAX_SESSION_DELTAS`) deltas of re-drain and overflow-suffix copying.
      Past it, the pass returns to RX and the run carries over
      (`ClosePermitBarrier::clear`), so the next pass parks the remaining
      blocked heads at once instead of holding RX for a fresh bound.

    The cost: with more blocked work than one budget, the deltas behind it
    wait a pass or more while RX polls. Each tick also tries every parked
    Close's permits twice, which is O(parked) while those permits stay held.

    A same-tuple reincarnation that overtakes it is safe:
    the flush's stale-incarnation fence makes the old Close's local teardown
    id-conditional, and when the EXACT key (scope included) now holds the
    reincarnation the old Close's HA legs are skipped altogether. The binary
    HA Close carries no id, so in routing domain 0 it would be a bare delete
    of the reincarnation on the peer (Codex R16 F1; see `afxdp/README.md`
    "A superseded stale Close sends no HA close"). That holds only for a
    reincarnation the peer hears of. A same-id re-materialization (#19047) is
    NOT a reincarnation: its newer promote Open can follow the parked
    Close (Codex observed `ha=[2,1]`).
  - **One order for the ring and the deferred overflow suffix (#10309).** An
    overflow Close that could not retire is kept in
    `deferred_expiry_overflow_deltas` and retried on later ticks AFTER the
    ring drains, never before it: the ring can hold an older Open/Update of
    the same session, and a Close must not overtake its own session's older
    delta (cycle 1 retired the suffix first and emitted Close before Open:
    Codex R15 P1#3). Deltas queued since the deferral also drain first. For
    the same session those are newer deltas of a re-materialized same-id row
    (a Close after them is the correct order) or a new incarnation (the
    Close is id-fenced at flush); different sessions carry no order.
  - `SessionTable::close_head_blocked` makes a blocked head cost one permit
    try per tick instead of a 256-delta drain and requeue. The post-RX
    export and loss-resync slices also leave a blocked head to housekeeping
    rather than re-draining it and `continue`ing past the loop bottom. The
    bit is set by whichever drain found the block (`drain_and_flush_all_impl`
    or the export slice); `ClosePermitBarrier::on_blocked` only asserts it.
  - Each park logs one rate-limited `xpf-dp: wN: #19026 session close
    parked after N us` line, at most one per 10 s process-wide. The line
    names the tuple and a `TupleGate::probe()` of the holder class.
  - **Residual: the parked tuple itself.** While a parked Close waits, RX
    polls, so a packet of that one tuple can re-materialize a same-id row from
    the still-published shared copy; that row outlives the Close and ages out
    on its own idle timer (the #10419 hazard, for the parked tuple only;
    #19047). Cycle 1 retired such a row with a bare
    `DeleteSynced(key)`, which could delete a queued replacement incarnation
    (Codex R15 P1#4), so that mechanism was removed.
  - Before #19026 the skip was unbounded. Because the heartbeat is stored
    before housekeeping, a worker whose Close never got its permit looked
    healthy while it polled no RX at all; #19032 tracks the detector gap.
  - `drain_and_flush_all_impl` also yields after a drain+flush pass that
    leaves the queue no shorter, instead of re-draining in-call.
  - Do not re-introduce an unbounded `return true` from housekeeping.
  - Cells: `loop_body/housekeeping_rx_starvation_19026_tests.rs`; the
    superseded-Close HA leg: `loop_body/superseded_close_ha_leg_19026_tests.rs`.
  - Not in this change (#19063): restored `SharedPromote` copies on several
    workers still each close at their own idle deadline, as on master. So a
    restored session's RT_FLOW Close is emitted once per copy, not exactly
    once, and nothing here claims otherwise. The restore close fence, the
    one-owner close obligation and the restart/RG-departure lifecycle are
    designed separately there.
- CPU pinning honors the inherited systemd `CPUAffinity=` mask. Worker
  N pins to the N-th *allowed* CPU in that mask, so
  `CPUAffinity=2 3 4 5` puts workers 0..3 on CPUs 2..5. Don't revert
  to absolute-index pinning; the `CPUAffinity=` test catches it.
- Each phase of #959 was a pure structural extraction — capacities
  and access semantics were preserved. Treat the sub-struct field
  layout as load-bearing for the cache-line story.
- `worker_loop` polls every binding once per tick in
  `RX_BATCH_SIZE = 64`-sized batches up to
  `MAX_RX_BATCHES_PER_POLL = 4` per tick. `RX_BATCH_SIZE` and
  `TX_BATCH_SIZE` carry compile-time `const_assert`s in
  `afxdp/mod.rs`; `MAX_RX_BATCHES_PER_POLL = 4` is a plain `const`
  there with a `const _: () = assert!(MAX_RX_BATCHES_PER_POLL >= 1);`
  compile-time guard in `worker/lifecycle.rs`. The guard pins the
  lower bound only — there is no compile-time pin on the value 4
  itself; change it deliberately and re-run the guarantee-phase
  per-visit budget tests (`guarantee_phase_visit_cap_drains_banked_frames`
  and `guarantee_phase_allows_larger_high_rate_visit_quantum`). #1630 (P2)
  split the per-visit budget into a rate-scaled Phase-1 cost
  (`cos_guarantee_quantum_bytes`) and a FRAME-count send cap
  (`cos_guarantee_visit_cap_bytes` = `TX_BATCH_SIZE × frame`); the
  `TX_BATCH_SIZE` const-assert covers the latter.
- Binding creation must publish the selected shared-UMEM mode/group/role
  into `BindingLiveState` for both private and shared paths before the
  first coordinator refresh. The coordinator treats the live snapshot as
  authoritative after worker start, so a bind path that only logs the
  kernel role but does not update live status will make the CLI report
  `Shared UMEM bindings: 0/N` even when the sockets are actually shared.
- `worker_loop`'s launch protocol is the 5 typed bundles in `launch.rs`
  (#6241), destructured at entry into the same locals the loop body used
  before. This is behavior-preserving (Refactor class A): the bundles are
  MOVED in and consumed once at entry — zero added clone / allocation /
  reference-indirection, and no bundle-shaped value survives in the
  10K–100K-tick/s loop. Do not add per-tick `self.shared.*` field access;
  keep the entry-destructure shape. `WorkerPublishedTelemetry.recent_exceptions`
  and `.last_resolution` carry a #6242 lifecycle contract that is now
  INTEGRATED: they are the SAME `Arc`s the worker's per-worker
  `WorkerRuntimeRecord` (`coordinator/worker_manager.rs`, keyed by
  `worker_id` in `workers.records`) owns. `bring_up_workers` allocates
  each once, retains one clone for the record and moves the original into
  this bundle — one shared allocation, no re-allocation. The record is
  registered as ONE `records.insert` AFTER the spawn succeeds, so the
  live worker and the record share the alloc for the worker's lifetime.
- `BindingWorker::new_for_cos_drain_test` is test-only scaffolding for
  hermetic CoS service-path tests. It uses in-memory AF_XDP ring fixtures
  and must not become a production construction path; production workers
  still go through `BindingWorker::create`, which performs the real bind
  and seeds ring/UMEM ownership from the binding plan.
