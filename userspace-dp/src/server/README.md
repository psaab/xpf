# userspace-dp/src/server/

Control-socket lifecycle and request dispatch. The Go daemon talks to
this surface over a Unix socket using a newline-delimited text protocol.

## Files

- `mod.rs` — module root, public API surface.
- `lifecycle.rs` — `run()` is the daemon entry called from `main.rs`.
  Argv parsing (`--workers N`, `--socket PATH`, etc.), socket setup,
  sysctl tuning, signal handling.
- `state.rs` — `ServerState`: coordinator handle, latest config
  snapshot, session-table handle, policy state.
- `handlers.rs` — request dispatch. Stateless handlers per request kind
  (`apply_snapshot`, `set_forwarding_state`, `set_queue_state`,
  `inject_packet`, `stop_workers`, `rebind`, …).
- `helpers.rs` — shared daemon-loop utilities (`replan_queues`,
  `replan_bindings_from_candidates`, `summarize_queues`, capability
  checks).

## Request protocol

Each request is one JSON object per line, response is one JSON object.
The shapes are mirrored in `pkg/dataplane/userspace/protocol.go` on the
Go side; **the JSON tags ARE the contract** — changing one without
updating the other breaks the helper.

## Reconciliation

`replan_queues` derives the binding plan from the current
`ConfigSnapshot`: enumerate userspace-candidate interfaces, count their
RX queues, and emit one `BindingStatus` per `(queue_id, interface)`
pair. The Rust planner does:

```rust
binding.worker_id = (queue_id % workers.max(1)) as u32;
```

so a clean 1:1 queue→worker mapping requires `queue_count == workers`.
The Go side ensures that via `pkg/daemon/rss_indirection.go` (mlx5
today; see #1243 kill record for why i40e doesn't reshape).

## Gotchas

- `defer_workers=true` requests skip the worker spawn until the next
  reconcile. Used during RETH MAC programming so workers don't bind to
  an interface that's about to drop and re-add its MAC.
- The control socket is shared with status poll, HA sync, session
  installs, snapshot sync, and forwarding sync. Adding a new caller at
  >1 Hz starves session installs during bulk sync.
