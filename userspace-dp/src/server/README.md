# userspace-dp/src/server/

Control-socket lifecycle and request dispatch. The Go daemon talks to
this surface over a Unix socket using a newline-delimited text protocol.

## Files

- `mod.rs` — module root, public API surface.
- `lifecycle.rs` — `run()` is the daemon entry called from `main.rs`.
  Argv parsing (`--workers N`, `--control-socket PATH`, etc.),
  socket setup (control + a derived dedicated session-install
  socket so session installs don't share the control channel),
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

`ConfigSnapshot.version` is a compatibility gate, not just documentation.
The helper accepts only the current snapshot protocol version; this prevents a
new daemon from publishing fields such as policy-scheduler inactive bits to a
helper that would silently ignore them.

## Reconciliation

`replan_queues` derives the binding plan from the current
`ConfigSnapshot`: enumerate userspace-candidate interfaces, count their
RX queues, and emit one `BindingStatus` per `(queue_id, interface)`
pair. The Rust planner does:

```rust
binding.worker_id = (queue_id % workers.max(1)) as u32;
```

so modulo assignment can map multiple queues onto the same worker
when `queues > workers`. The Go side's
`pkg/daemon/rss_indirection.go` reshapes RSS indirection only on
**mlx5** drivers and only when `workers > 1 && workers < queues`,
concentrating traffic onto queues `0..workers-1` (it does not change
the Rust planner's `queue_count`). With `workers == 1` it leaves the
live RSS table untouched (single worker drains all queues), and on
non-mlx5 drivers (i40e, etc.) it doesn't reshape at all. The default
RSS table is restored either when the kill switch fires
(`enabled == false`), or via `maybeRestoreDefault()` on the
`workers > 1 && workers >= queues > 1` path — there to undo a
concentrated table left by an earlier `workers < queues`
configuration (#805). On non-mlx5 + `workers > 1 && workers <
queues`, modulo collision can leave one worker bound to multiple
queues. See PR #1243's kill record for why i40e doesn't reshape.

## Gotchas

- `defer_workers=true` requests skip the worker spawn until the next
  reconcile. Used during RETH MAC programming so workers don't bind to
  an interface that's about to drop and re-add its MAC.
- Session installs run on a **dedicated** session-install socket
  (`derive_session_socket_path` next to the control socket), so they
  do not share the control-channel queue with status poll, HA sync,
  snapshot sync, and forwarding sync. The control channel is still
  shared by those other callers; adding a new caller there at >1 Hz
  can still starve the other low-frequency control operations.
