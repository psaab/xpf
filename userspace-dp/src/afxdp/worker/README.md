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
| `loop_body/ct_slice.rs` | #13075 per-tick conntrack refresh and fabric/WG drains (`run_ct_slice`, `#[inline(never)]`); also the pending-neighbor retry timer. The #16217/#16223 shared-evidence block walks the worker's WHOLE table each time it runs. Worker replication puts every session in every worker's table, so a whole-table walk covers the node's entire session population. The block (`run_shared_evidence_leg`) therefore runs once per refresh cycle (its first slice), not on each of the cycle's ceil(slab / 2048) slices. It stays O(n + N) per run. It takes the global shared-map mutexes for batched count restamps, `CtSlicePairSet` dedup and one `shared_rows_stage_and_counts` pass, plus one short acquisition of both maps per not-yet-complete forward row (`node_served_forward_slice` → `shared_completion_evidence`), so acquisitions are O(n) per run; #18662 tracks bounding that (#18655, where a per-key whole-map scan stalled the dataplane at 4000 sessions and a per-slice whole-table walk still saturated the mutexes at 16000). Latency bound: a completed pair's shared stage advances within max(CT_REFRESH_WINDOW_NS, ceil(slab / 2048) × CT_SLICE_INTERVAL_NS) of its completion: 10 s at the default cap; HA imports can stretch it to about 13 s. `upsert_synced_with_origin` has no per-table cap, so with a correct peer a table peaks near 2× the cap when both nodes' populations meet (128 slices). The only hard import bound, #5674's shared-map ceiling, is looser (#18687). That is inside the 20 s TCP opening window for a pair that completes early enough in its replica's window; one that completes late (a SYN retried at 15 s, say) can still be reaped first. A const assert in `loop_body/slice_pacing.rs` fails the build if the default cap or the windows would break this bound. |
| `loop_body/delta_recovery.rs` | #13075 per-tick delta-loss recovery and stale-session sweeps (`run_delta_recovery`, `#[inline(never)]`). |
| `loop_body/debug_report.rs` | #1776 cfg(debug-log)-only counters, per-second report, and stall dump; compiled out of release builds. |
| `loop_body/export_slice.rs` | #13075 per-tick CommandExport slice and steady-state delta drain (`run_export_slice`, `#[inline(never)]`). |
| `loop_body/gc_teardown.rs` | #13075 session-expiry/GC and control-plane delete teardown helpers, re-exported for worker call sites. |
| `loop_body/housekeeping.rs` | #13075 per-tick session expiry/GC housekeeping and close-delta drain (`run_session_housekeeping`, `#[inline(never)]`). |
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
