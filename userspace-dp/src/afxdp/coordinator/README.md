# userspace-dp/src/afxdp/coordinator/

The single owner of cross-worker state and lifecycle. Constructs the
binding plan, spawns workers under the supervisor, holds the shared
BPF map handles and HA snapshot, and exposes the operator-facing
status surface to `server/` for the daemon's gRPC / HTTP queries.

This is the orchestration layer that sits *above* the per-worker
dataplane: workers take ownership of an AF_XDP socket and a
binding's hot path (see `worker/`); the coordinator owns everything
the workers share.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `Coordinator` struct + worker-spawn + reconcile entry. |
| `bpf_maps.rs` | `BpfMaps` — pinned BPF map FDs (XSK map, heartbeat, session, conntrack v4/v6) opened once and shared with every worker. |
| `cos_state.rs` | `SharedCoSState` — Arcs that workers consult to find owner-by-queue, live owner, root/queue leases, vtime floors. |
| `ha_state.rs` | `HaState`: HA snapshot, shared fabrics, forwarding state. (RG epoch counters live on `Coordinator` itself in `mod.rs`, not here.) |
| `inject.rs` | `request inject-packet` RPC handler — synthesizes a packet against the live state, reports disposition. |
| `neighbor_manager.rs` | `NeighborManager` — sharded ARP/NDP cache + netlink monitor for incremental updates. |
| `session_manager.rs` | Cross-thread session-table state shared between coordinator, HA worker, and packet workers via `Arc<Mutex<...>>`. Holds the synced + nat + forward-wire tables together because they're written and queried as a unit. |
| `status.rs` | Read-side snapshots for `show ...` queries. The exception is `drain_session_deltas`, which mutates per-binding state. |
| `supervisor.rs` | `spawn_supervised_worker` / `spawn_supervised_aux` — catches panics, marks the worker dead on its `WorkerRuntimeAtomics`, captures a panic message into a per-worker slot. (#925 Phase 1.) |
| `worker_manager.rs` | Per-worker lifecycle and planning state. **Two key spaces:** `live` and `identities` are keyed by binding `slot`; `handles` is keyed by `worker_id`. Don't conflate them. |

## Where it sits

- Above: `server/handlers.rs` calls into `Coordinator::*` for every
  control-socket RPC.
- Below: spawns and manages the per-worker poll loop in `worker/`.
- Sideways: shares `BpfMaps` and `SharedCoSState` Arcs with workers.

## Notable invariants

- The coordinator is the single owner; workers hold `Arc` clones.
  Lifetime hazards from breaking that invariant are how cross-binding
  redirect designs have died historically (see `docs/per-5-tuple/state.md`).
- Worker spawn happens via the supervisor; never call
  `std::thread::spawn` directly for a worker — it bypasses the panic
  capture.
- `defer_workers=true` on `apply_snapshot` skips spawn until the next
  reconcile (used during RETH MAC programming so workers don't bind
  to an interface that's about to drop and re-add its MAC).
