# userspace-dp/src/afxdp/

Primary #1373 AF_XDP forwarding path. New dataplane hot-path work belongs here
or in the adjacent userspace modules unless a legacy eBPF regression/rollback
need is explicit.

The hot path. Coordinator + per-worker threads + UMEM + RX/TX/fill/
completion rings + frame parsing + session glue + neighbor cache + HA
sync.

## Submodules

- `coordinator/` — spawns and supervises workers, owns the binding
  plan, tracks worker liveness (`#925`), publishes status snapshots,
  receives lifecycle commands from the control socket. `mod.rs` is the
  single entry that owns shared state Arcs; `worker_manager.rs` keeps
  the per-worker handle table.
- `worker/` — the per-worker poll loop (`mod.rs` runs the dispatch).
- `poll_stages.rs` — sibling of `worker/`, not inside it. Holds the
  per-packet pipeline stages extracted in #946 Phase 1.
- `frame/` — packet parsing (L2 / L3 / L4), checksum helpers, TCP MSS
  clamp. `tests.rs` was relocated out of `mod.rs` in #1046 Phase 1.
- `umem/` — UMEM allocator, fill ring, completion ring. Frames are
  4 KB (`UMEM_FRAME_SIZE = 4096`); index is `addr >> 12`.
- `tx/` — TX ring management, batched enqueue, TSO segmentation
  (`tx/tcp_segmentation.rs` after PR #1199), per-binding TX counters.
- `cos/` — Class-of-Service scheduler: token-bucket admission, MQFQ
  active-bucket selection, fair-share lease (#1229 Phase 6 v8). See
  `docs/per-5-tuple/state.md` for the architectural ceiling.
- `forwarding/` — FIB lookup, next-hop selection, VLAN/GRE encap.
- `event_emit.rs` — fixed-size, non-blocking RT_FLOW event producers
  for userspace policy-deny, screen-drop, and logged PBR filter hits.
  Producers must use the event-stream worker handle so rate limiting,
  queue-budget accounting, replay, and daemon callback ACK behavior stay
  centralized in `event_stream/`.
- `session_glue/` — bridges the userspace session table back to the
  BPF session map mirror so the CLI / GC see the same sessions.
- `types/` — shared structs: `BindingPlan`, `BindingStatus`,
  `WorkerRuntimeAtomics`, `SharedCoSQueueLease`, `BatchCounters`, …

## Hot-path constants

- `RX_BATCH_SIZE = 64`
- `TX_BATCH_SIZE = 64`
- `MAX_RX_BATCHES_PER_POLL = 4`
- `FILL_WAKE_SAFETY_INTERVAL_NS = 500_000` (lost-wakeup safety net)
- `HEARTBEAT_GRACE_PERIOD_NS = 6 * 1_000_000_000`

These are paired with cache-footprint and CoS-quantum invariants —
const-asserts catch unintentional changes.

## CPU pinning

`worker::pin_current_thread(worker_id)` (in `neighbor.rs`) honors the
inherited systemd `CPUAffinity=` mask. Worker N pins to the N-th
*allowed* CPU in that mask, so `CPUAffinity=2 3 4 5` puts workers
0..3 on CPUs 2..5 — outside the default mask but inside the unit's.
Don't revert to absolute-index pinning; the `CPUAffinity=` test catches
it explicitly.

## Reading order

`coordinator/mod.rs` for ownership and lifecycle, then
`worker/mod.rs` for the dispatch, then the sibling `poll_stages.rs`
for the per-packet stages, then peer modules as needed.
