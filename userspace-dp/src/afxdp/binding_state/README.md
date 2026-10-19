# userspace-dp/src/afxdp/binding_state/

Per-binding live runtime state — the `BindingLiveState` atomics
cluster that the worker hot path writes and the control/status paths
read: ring state, forwarding/session/screen/NAT counters, owner/peer
telemetry profiles, debug gauges, the cross-worker redirect TX inbox,
and the HA session-delta RPC-fallback buffer.

Extracted from `../umem/` in #6436 — `umem/` is now only the UMEM
memory region; this module is everything per-binding that is *not*
the memory region. The move was pure code-motion: no field
reordering (drop order is load-bearing where documented), atomic
orderings and `#[inline]` attributes moved byte-identical, and the
`const _: () = assert!` layout guards travel with their items.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | `BindingLiveState` — the per-binding atomics cluster + constructor + setter/counter impl block. `SharedUmemLiveStatus`, `FlowWorkerMapSnapshot`. Re-exports the submodule items at `pub(in crate::afxdp)` (E0364 precedent per `tx/mod.rs`). |
| `tx_inbox.rs` | The bounded lock-free MPSC redirect inbox (`pending_tx`) and its linearizable admission counter: `enqueue_tx` / `enqueue_tx_owned` / `try_enqueue_tx_owned` / `take_pending_tx_into`, plus the `PendingTxAdmission` RAII single-release token (mirror reservation path). |
| `latency.rs` | `bucket_index_for_ns` + the histogram bucket-count wire-contract constants (`DRAIN_HIST_BUCKETS`, `TX_SUBMIT_LAT_BUCKETS`), the producer-local redirect-sample TLS (`REDIRECT_SAMPLE_SEQ` + `REDIRECT_SAMPLE_MASK`), and `TX_SIDECAR_UNSTAMPED`. |
| `session_delta.rs` | The HA session-delta RPC-fallback buffer (`pending_session_deltas`) + the #5290 `delta_loss_pending` loss-of-sync latch that drives the full owner-RG resync. |
| `snapshot.rs` | `BindingLiveState::snapshot()` — the operator-facing `BindingLiveSnapshot` render (~120 Relaxed loads, bounded read-skew contract). |
| `kernel_stats.rs` | `BindingLiveState::publish_kernel_xdp_statistics` — the ONE site that turns a `statistics_v2()` sample into per-binding atomics. Destructures `XdpStatisticsV2` exhaustively, so a new kernel counter is a compile error here rather than a field that reaches the wire unwritten (#9168). `UNPLUMBED_KERNEL_STAT_FIELDS` names the counters deliberately not carried. |
| `debug_state.rs` | The ~65ms debug-state publish cadence (`update_binding_debug_state` / idle variant) that flushes worker-local scratches into the binding atomics. |
| `profile.rs` | `OwnerProfileOwnerWrites` / `OwnerProfilePeerWrites` — cacheline-isolated (`#[repr(align(64))]`) telemetry blocks, split by writer. |
| `tests/` | Co-located unit tests, per-concern split (#4667, relocated from `umem/tests/` in #6436): `mod.rs` (shared `use` header + the cross-concern `test_tx_request_for_inbox` fixture), `tx_inbox.rs`, `latency_buckets.rs`, `snapshot_propagation.rs`, `tx_submit_latency.rs`, `tx_kick_latency.rs`, `debug_state.rs`. |

## Notable invariants

- **`BindingLiveState` is touched per-packet.** Field order is fixed
  (drop order is load-bearing where documented); hot-path atomic
  orderings are part of the contract. Owner-written telemetry is
  cacheline-isolated from peer-written telemetry (`profile.rs`,
  enforced by compile-time align/size asserts).
- **Kernel XDP statistics have ONE publisher, and it destructures
  exhaustively** (#9168): `statistics_v2()` returns six counters. Before
  #9168 the worker loop stored one of them inline and dropped the rest,
  two of which (`rx_dropped`, `rx_invalid_descs`) had a complete consumer
  chain all the way to the operator's `Kernel RX dropped:` /
  `Kernel RX invalid:` lines — so those lines reported a permanent hard
  `0`, the healthy value, on the instrument that exists to reveal a NIC
  dropping every packet. `publish_kernel_xdp_statistics` is now the only
  site that converts a sample, it binds every field by name, and a
  counter it deliberately does not carry must be listed in
  `UNPLUMBED_KERNEL_STAT_FIELDS`. Kernel counters are ABSOLUTE per
  socket, so they are published with `store()`, never `fetch_add()`.
  #15285 carries `rx_ring_full` as `kernel_rx_ring_full` per binding/queue
  through snapshot, wire, Go status/monitor, and the
  `xpf_userspace_binding_kernel_rx_ring_full_total` metric; the remaining
  unplumbed fields are `tx_invalid_descs` and `tx_ring_empty_descs`.
- **Redirect inbox admission is linearizable via
  `pending_tx_admitted`, not `pending_tx.len()`** — the atomic
  acquire/release pair brackets the MPSC push, and the
  `PendingTxAdmission` RAII token guarantees exactly one release per
  reservation (disarm-on-push; `Drop` releases only if still armed).
  Drop-newest on overflow (see `tx_inbox.rs` for the rationale).
- **The redirect-acquire sampler is producer-local** (#5160):
  `REDIRECT_SAMPLE_SEQ` is a thread-local `Cell<u64>`, so the
  many-producer redirect hot path pays no shared RMW per enqueue;
  only the sampled 1-in-256 op writes the destination's
  `redirect_acquire_hist`.
- **Session-delta loss latches a full resync** (#5290): a dropped or
  undrained RPC-fallback delta arms `delta_loss_pending`; the owning
  worker folds it into `SessionTable::set_delta_loss` so the standby
  recovers via table-truth re-export instead of silently diverging.
- **...but the resync's OWN deltas must not arm it (#8593).** The resync
  is a full owner-RG export, and it publishes through
  `flush_session_deltas` into THIS buffer — which its chunked drain does
  not empty (that drain empties the `SessionTable` ring) and which the Go
  side polls on the ~5 s `DrainSessionDeltas` cadence. So the export
  overflows the buffer whose overflow triggered it, and re-arms.
  Measured on `loss:xpf-userspace-fw0`: 125,780 session creates produced
  25.26M deltas of which 23.29M (92%) were dropped, and with the
  generator stopped and `active_flow_count = 0` the helper kept
  generating ~149k deltas/s for ~90 s, ending only as the owned sessions
  aged out. The signature was 32.68M dropped session-CREATE deltas
  against 52k dropped closes — re-exported opens, not traffic.
  `SessionDelta::bulk_resync` marks the export's own deltas and
  `push_session_delta_bulk_export` counts their drops without arming.
  The marker rides on the DELTA rather than a flag at the flush call
  site because a call site that passed the flag wrongly would SUPPRESS a
  genuine arm, silently; a producer that sets it cannot be got wrong by a
  new drain site. Not-arming is also the correct answer, not merely the
  loop-safe one: the recovery is an OPEN-ONLY snapshot of the owned set,
  so it cannot restore a dropped CLOSE however many times it runs, and
  every OPEN it could restore is already in the snapshot being shipped.
  The same non-arming rule holds on the lossless event-stream leg
  (#14646): a `bulk_resync` delta whose `push_delta_lossless_within`
  fails (disconnected stream / bounded timeout) counts in
  `frames_dropped` but does not set `event_stream_out_of_sync`, so the
  worker loop's `set_delta_loss` is never re-armed by the export itself.
- **Status-snapshot `last_error` precedence (#4971 / #6145).**
  `snapshot()` (`snapshot.rs`) renders `last_error` from TWO sources with
  a fixed precedence: the `last_error` **mutex** string (written by the
  exceptional `TxError::Drop` / bind / reconcile paths via `set_error`)
  wins whenever non-empty; only when it is empty does the snapshot fall
  back to the lock-free `last_tx_retry_status` atomic (the expected-TX
  backpressure hint from #4971). Consequence: a latched `TxError::Drop`
  **masks** a live retry hint until the binding rebinds and
  `clear_error()` resets both. This stale-masking is intentional — a
  Drop is rarer and more severe than routine backpressure — and is
  pinned by `tx_status_drop_error_outranks_retry_hint_until_rebind_6145`
  (`tests/snapshot_propagation.rs`). See `../tx/README.md` for the full
  rationale.
