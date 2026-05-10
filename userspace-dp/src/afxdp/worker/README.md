# userspace-dp/src/afxdp/worker/

The per-worker hot path. One `BindingWorker` per RSS queue, owns
its AF_XDP socket + UMEM + RX/TX/fill/completion rings + per-worker
state. The `worker_loop` in this module's `mod.rs` calls
`poll_binding` once per binding per tick.

`BindingWorker` was decomposed into sub-structs in #959 (Phases 1–11).
Each phase extracted one cluster of fields into a dedicated
sub-struct so the parent struct stays cache-line-friendly and so
each cluster has a clear ownership boundary.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `worker_loop`, `BindingWorker` struct, `pin_current_thread`. |
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
| `flow_cache_state.rs` | `WorkerFlowCacheState` (#959 Phase 9) — per-worker flow cache + 64-touch refresh boundary. |
| `xsk_rings.rs` | `WorkerXskRings` (#959 Phase 11) — the three XSK kernel-ring handles (`device`, `rx`, `tx`). |

## Where it sits

- Top of the dataplane stack. Spawned by `coordinator/supervisor.rs`.
- Reads/writes to all the AF_XDP sub-modules (`umem/`, `tx/`,
  `frame/`, `cos/`, `forwarding/`, `session_glue/`).
- After #959, fields are accessed via the sub-struct prefix
  (`binding.cos.cos_X`, `binding.scratch.scratch_X`, etc.) — see the
  memory note `959_done` for the field-access map.

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
  `MAX_RX_BATCHES_PER_POLL = 4` per tick; both constants pinned by
  `const_assert` in the parent module.
