# userspace-dp/src/afxdp/tx/

The TX side of a binding: classify into a CoS queue, dispatch
through the queue service, drain shaped queues, segment large TCP
frames, submit to the kernel's TX ring, reap the completion ring,
and recycle UMEM frames.

Every file here is **single-writer (owner worker)**. Atomic
operations use `Ordering::Relaxed` because there is no second
writer to synchronize against.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub. |
| `cos_classify.rs` | Maps a packet's policy / filter / classifier signals to a CoS queue id and an optional DSCP rewrite, then enqueues onto the chosen queue. |
| `dispatch.rs` | Batch dispatch from descriptor loop into the CoS queue runtime; handles fast-path interface lookup and falls back to the CoS engine. |
| `drain.rs` | Per-tick drain dispatch + queue-bound / pending-queue helpers. Owns the `COS_GUARANTEE_QUANTUM_*` and `COS_GUARANTEE_VISIT_NS` constants. |
| `rings.rs` | XSK kernel-ring discipline: completion drain, fill submit, RX/TX kernel wake. |
| `stats.rs` | Per-frame counters and submit-latency histogram bucketing. The sidecar `&mut [u64]` is non-atomic since it's owner-only. |
| `tcp_segmentation.rs` | TCP segmentation for forwarded frames (extracted in PR #1199). `#[cold]` — segmentation is the slow path; line-rate flows don't enter it. |
| `transmit.rs` | XSK TX-ring submit + per-frame recycle. Owns `transmit_batch`, `transmit_prepared_queue`, shared-UMEM-aware prepared recycle helpers, and the `TxError` enum. |
| `test_support.rs` | Test helpers for the per-file unit tests. |

## Where it sits

- Driven from `worker/lifecycle.rs::poll_binding`.
- Reads decisions from `forwarding/` and CoS state from `cos/`.
- Writes to UMEM via `umem/` and to the kernel via `xsk_ffi`.

## Notable invariants

- Single-writer per binding: every TX path here runs on the binding's
  owner worker. Cross-binding redirect (the only legitimate
  cross-worker writer) lives in `cos/cross_binding.rs` and uses an
  MPSC inbox plus slot-routed prepared recycle records to release
  source UMEM frames after copy.
- Prepared-frame discard paths are not local by default in shared-UMEM
  mode. Any path that drops, demotes, bounds, cancels, or rejects a
  `PreparedTxRequest` must call the `_with_shared` recycle helper while
  carrying the worker's shared recycle accumulator, then route the
  `(slot, offset)` records back through the shared slot-resolution helper.
  The split-slice path used while holding the ingress binding and the
  all-bindings cleanup path must share this resolver so stale lookup entries
  are handled identically. Unknown recycle slots must fail closed and
  increment `tx_errors` on the worker status surface with bounded one-line
  logging per drain; never push a foreign offset into an arbitrary binding's
  fill ring.
- `Ordering::Relaxed` is intentional and correct given the
  single-writer invariant. Don't promote without proving a second
  writer exists.
- TCP segmentation is `#[cold]`. The fast path is direct submit;
  segmentation only fires for over-MSS forwarded frames.
