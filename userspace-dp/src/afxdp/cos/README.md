# userspace-dp/src/afxdp/cos/

Class-of-Service scheduler. Per-egress-interface shaping, per-queue
priorities, per-flow fair share inside a queue, ECN CE-marking, and
the cross-binding redirect path that gets a TX request to the
worker that owns the egress interface.

This is the most complex sub-module in the dataplane and the place
where every recent fairness mechanism kill happened (#1236, #1237,
#1239, #1243, #1244 — see `docs/per-5-tuple/state.md`).

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Re-export hub for the sub-modules. |
| `admission.rs` | Per-flow admission gates (share / buffer caps, ECN CE-marking) + flow-fair (SFQ) queue promotion. |
| `builders.rs` | CoS interface-runtime construction. `ensure_cos_interface_runtime` sits on the steady-state enqueue path (every enqueue checks whether the runtime exists for the egress ifindex) and is `#[inline]`. |
| `cross_binding.rs` | Cross-binding redirect: routes a TX request to the owner binding of the egress, for both `Local` and `Prepared` variants. Prepared redirects release source UMEM frames through the TX shared-recycle accumulator so foreign-slot frames return to their owning fill rings. |
| `ecn.rs` | ECN CE-marking + Ethernet L3 parser. Threshold constants and the `apply_cos_admission_ecn_policy` gate live in `admission.rs` (a byte-mutation module shouldn't own admission tuning). |
| `fairness.rs` | #1229 v7 per-bucket TX rate accounting + threshold-gated EWMA. Tracks observed bits/sec per FlowFair bucket so the cap-aware MQFQ selector can compare against `Queue_BW_bps / max(1, active_flow_buckets)`. Single-writer per `FlowFairState`. |
| `flow_hash.rs` | Per-queue flow-hash machinery for SFQ admission + promotion. |
| `queue_ops/` | CoS queue primitives: accessors, enqueue/dequeue, MQFQ ordering bookkeeping, V-min slot lifecycle. Per-byte hot-path fns carry `#[inline]` to preserve cross-module inlining. |
| `queue_service/` | CoS dispatch / drain / submit subsystem. Hot-path call chain: `drain_shaped_tx → select_cos_*_batch → service_exact_*_queue_direct → drain_exact_*_to_scratch → submit_cos_batch → settle_exact_*`. |
| `token_bucket.rs` | Token-bucket lease / refill plumbing for TX pacing. Owns `COS_MIN_BURST_BYTES` (64 × MTU) — the universal floor for both root and per-queue burst caps. |
| `tx_completion.rs` | TX-completion + interface timer wheel. Owns the wheel advance / cascade / wake-due slot management, the apply paths (`apply_direct_exact_send_result`, `apply_cos_send_result`, `apply_cos_prepared_result`), and the queue-scoped `DrainShape` phase counters (`guarantee`, `surplus`, `nonexact_while_exact_backlogged`). |

`queue_ops/` and `queue_service/` are sub-directories; see their own
mod.rs for further file-level breakdown.

## Where it sits

- Reads decisions from `policy.rs` (forwarding-class + DSCP rewrite).
- Driven from `tx/dispatch.rs` and `worker/lifecycle.rs::poll_binding`.
- Writes per-queue / per-binding state held in `types/cos.rs`.
- Owner-only writes; cross-binding `cross_binding.rs` is the only
  legitimate path that crosses worker boundaries.

## Notable invariants

- Single-writer per FlowFairState. The owner worker that polls a
  binding is the same worker that owns the queue's
  `FlowFairState`; therefore `observed_bps` updates and reads do not
  need atomic synchronization.
- Prepared CoS items may carry frames from another binding in the same
  shared-UMEM group. Queue overflow, capacity rejection, local
  demotion, cross-binding copy, and runtime reset must thread the
  worker shared-recycle accumulator to avoid returning a foreign slot's
  frame to the current binding.
- Hot-path constants pinned in code: `RX_BATCH_SIZE = 64`,
  `TX_BATCH_SIZE = 64` (the latter paired with the CoS guarantee
  quantum). See `userspace-dp/README.md`.
- Per-byte hot-path fns are `#[inline]` to preserve cross-module
  inlining across the `pub(in crate::afxdp)` boundary; the larger
  drain/settle bodies aren't inlined (LLVM heuristics suffice).
- The TX drain caller enters `drain_shaped_tx` only while the binding
  reports at least one nonempty CoS interface and has an interface order.
  Configured-but-idle bindings skip the no-op shaped-drain call path
  entirely; nonempty bindings still call into CoS so runnable work,
  due parked queues, and shared lease epoch progress are preserved.
- `drain_shaped_tx` primes an interface root only when queued work is
  runnable now or a parked queue's wake tick is due. Not-yet-due
  parked queues skip timer-wheel advance and shared-root lease top-up
  because no queue can service on that drain call.
- Scheduler-map queues without a positive explicit scheduler
  `transmit-rate` are residual-only under a shaped root. They keep an
  effective rate for burst sizing and surplus weight, but
  `queue_service` skips them in guarantee selectors via
  `queue.config.guarantee_enabled == false`.
- Residual-only / non-exact queues keep their explicit guarantee
  service, but their surplus service is filtered while exact queues
  have demand on the same shaped interface. Local exact demand must be
  runnable with root and per-queue tokens available, so an exact queue
  that is parked on its own rate cap does not idle the root. Peer
  binding serviceable backlog is imported through
  `SharedCoSExactBacklog` using release/acquire atomics; that signal
  protects the common cross-binding case but can only be as fresh as
  the peer's latest publish. Exact queues that explicitly enable
  `surplus-sharing` remain eligible for surplus service under this
  gate.
- `COS_MIN_BURST_BYTES` (64 × MTU) is canonically owned by
  `token_bucket.rs`; siblings import it via the `cos/mod.rs`
  re-export.
