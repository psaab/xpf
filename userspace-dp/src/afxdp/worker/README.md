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
`refresh_runtime_view` (#6291/#6592), remains `#[inline]`; production's
`between` closure is a zero-sized no-op, so the helper leaves no
release call boundary.

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
| `mod.rs` | `BindingWorker` struct + shared-binding helpers + `pub(crate) use loop_body::worker_loop` re-export + `pub(crate) use launch::{…}` bundle re-exports (#6241). |
| `loop_body/mod.rs` | `worker_loop` steady-state orchestrator (extracted in #1326 Phase 1; decomposed in #1776 and #13075). The per-tick call ordering stays here while selected control slices are `#[inline(never)]` calls into sibling modules. #6241: `worker_loop` takes 5 typed launch bundles (see `launch.rs`) and destructures them at entry into the same locals used today. |
| `loop_body/housekeeping.rs` | #13075 — per-tick session expiry/GC housekeeping and close-delta drain (`run_session_housekeeping`, `#[inline(never)]`). |
| `loop_body/pptp_drain.rs` | #13075 — per-tick PPTP control-inbox drain (`run_pptp_control_drain`, `#[inline(never)]`). |
| `loop_body/ct_slice.rs` | #13075 — per-tick conntrack refresh and fabric/WG drains (`run_ct_slice`, `#[inline(never)]`); also the pending-neighbor retry timer. |
| `loop_body/delta_recovery.rs` | #13075 — per-tick delta-loss recovery and stale-session sweeps (`run_delta_recovery`, `#[inline(never)]`). |
| `loop_body/export_slice.rs` | #13075 — per-tick CommandExport slice and steady-state delta drain (`run_export_slice`, `#[inline(never)]`). |
| `loop_body/reconcile.rs` | #13075 — forwarding-snapshot rotation reconciliation helpers, including the `#[inline]` `refresh_runtime_view` refresh seam. |
| `loop_body/gc_teardown.rs` | #13075 — session-expiry/GC and control-plane delete teardown helpers, re-exported for worker call sites. |
| `loop_body/screen_status.rs` | Publishes the worker's cumulative ScreenState status through a live binding on the report tick. |
| `launch.rs` | #6241 — the 5 typed worker-launch bundles (`WorkerLaunchPlan`, `WorkerSharedDataplane`, `WorkerControlChannels`, `WorkerCoSState`, `WorkerPublishedTelemetry`) + 2 nested (`WorkerNeighbors`, `WorkerSharedSessions`) that replace the old 38-parameter positional `worker_loop` protocol. `WorkerSharedDataplane::from_coord` / `WorkerCoSState::from_coord` (coordinator-published state) and the `::new` builders (per-worker slots) are the single named construction sites; `Arc::ptr_eq` wiring tests bind them (fail-on-revert for the session-map and heartbeat/export-ack silent-swap hazards). |
| `loop_body/setup.rs` | #1776 — one-shot cold setup (`worker_loop_setup`): thread pin via `pin_current_thread` (defined in `afxdp/neighbor.rs`), TSC calibration, binding construction, BPF-map-FD cache; returns `WorkerLoopSetup`. #6245: binding construction now accumulates EXPLICIT per-slot terminal failures (`binding_failures`) + recovered shared-group fallbacks (`recovered_fallbacks`), sorted deterministically and carried through `WorkerLoopSetup` into `WorkerStartupReport` (the failed slot is no longer signalled only by OMISSION from `bindings`). See `coordinator/README.md` #6245. |
| `loop_body/debug_report.rs` | #1776 — cfg(debug-log)-only `DbgCounters` + per-second verbose report (`emit_periodic_report`) + stall dump (`check_and_dump_stall`). #5189: also the per-binding diagnostics build (`build_binding_summary` — `String` + per-binding `statistics_v2()`/`SO_ERROR` `getsockopt`), which #1776 had left inline and ungated in `loop_body/mod.rs`. Compiled out of release builds. |
| `loop_body/idle_poll.rs` | #6431 — `#[inline]` classification of the Interrupt-mode idle-regulation `poll(2)` return (`classify` -> `Waited` / `Interrupted` / `Degraded`, plus `fault_summary` for the caller's one-shot log). |
| `lifecycle.rs` | `poll_binding` — the per-poll RX/TX orchestrator. The "central function" extracted in Issue 73 step 2. |
| `cos.rs` | Per-worker CoS runtime helpers + shared-exact threshold (the empirical sustained per-worker exact throughput ceiling — see comment block in the file for the evidence basis). |
| `cos_state.rs` | `WorkerCos` (#959 Phase 3) — per-binding CoS-engine state. |
| `cos_tests.rs` | Co-located CoS unit tests. |
| `telemetry.rs` | `WorkerTelemetry` (#959 Phase 1) — `dbg_*` debug counters. |
| `scratch.rs` | `WorkerScratch` (#959 Phase 2) — pre-allocated per-poll reusable buffers. |
| `tx_counters.rs` | `WorkerTxCounters` (#959 Phase 4) — per-binding TX-disposition packet counters (direct, copy, in-place + 3 fallback paths). |
| `bpf_maps.rs` | `WorkerBpfMaps` (#959 Phase 5) — four BPF map FDs opened once at construction (heartbeat, session, conntrack v4/v6). |
| `timers.rs` | `WorkerTimers` (#959 Phase 6) — five fields gating per-binding wake / heartbeat pacing. |
| `tx_pipeline.rs` | `WorkerTxPipeline` (#959 Phase 7 + Phase 10's `outstanding_tx`) — eight fields holding the TX pipeline buffers. |
| `bind_meta.rs` | `WorkerBindMeta` (#959 Phase 8) — `bind_time_ns`, `bind_mode` (copy vs ZC), and identity. |
| `flow_cache_state.rs` | `WorkerFlowCacheState` (#959 Phase 9) — per-worker flow cache. (#2220 dropped the binding-global modulo-64 `flow_cache_session_touch` keepalive counter; the cache fast path now calls `SessionTable::touch_if_stale`, a per-session time-threshold keepalive — see `session/README.md` "Flow-cache keepalive".) |
| `xsk_rings.rs` | `WorkerXskRings` (#959 Phase 11) — the three XSK kernel-ring handles (`device`, `rx`, `tx`). |

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
