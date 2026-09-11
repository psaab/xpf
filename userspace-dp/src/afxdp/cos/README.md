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
| `flow_hash.rs` | Per-queue flow-hash machinery for SFQ admission + promotion. The bucket key is the flow's 5-tuple plus its routing domain and tunnel discriminator, each mixed only when non-default, so identical 5-tuples in two routing instances or two GRE tunnels share a bucket only by chance, never by construction (#9645). |
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

- **Flow-fair gate is `flow_fair_state.is_some()` (#1735).** The runtime
  `CoSQueueRuntime::flow_fair()` accessor returns
  `flow_fair_state.is_some()`, NOT `config.flow_fair`. The invariant
  `flow_fair() == flow_fair_state.is_some()` is therefore structurally
  unbreakable — a `None`-state queue always dispatches the cheap FIFO
  branch and allocation is the only thing that flips the gate.
  `config.flow_fair_eligible` (the renamed `config.flow_fair`) means
  "this shaped queue MAY ever run flow-fair MQFQ" and is decoupled from
  the runtime gate.
- **Per-flow MQFQ runs on ALL shaped queues, not just exact (#1735).**
  `promote_cos_queue_flow_fair` marks every queue that reaches it
  (exact AND non-exact) `flow_fair_eligible`. Exact queues promote
  EAGERLY at build (allocate `FlowFairState` immediately, never demote —
  their V_min / v8-lease coordination assumes stable state). Non-exact
  eligible queues (best-effort / residual) promote LAZILY: a hash-free
  front-key contention probe in `cos_queue_push_back`
  (`maybe_promote_best_effort`) compares the incoming item's
  `Option<&SessionKey>` to the FIFO front structurally (NO hash) and
  promotes only on the FIRST genuinely-distinct flow. A single-flow /
  uncontended best-effort queue stays a trivial FIFO and pays zero hash
  and zero `FlowFairState` footprint — the #1183 best-effort fast-path
  boundary. Forwarding-only / transparent interfaces never build a
  `CoSInterfaceRuntime`, so their queues never become eligible.
  `promote_to_flow_fair` migrates the resident FIFO by re-enqueueing
  each item through the normal MQFQ accounting path (hashing each into
  its own bucket — correct for any flow mix). When a lazily-promoted
  non-exact queue settles fully drained for
  `COS_DEMOTE_EMPTY_SETTLE_HYSTERESIS` consecutive batch settles,
  `maybe_demote_drained_best_effort` (called at the end of
  `apply_cos_send_result` / `apply_cos_prepared_result`, after the retry
  restore) drops its `FlowFairState` box so idle queues release the
  ~232 KB footprint. Surplus DWRR across queues + MQFQ inside the
  selected queue compose for free: `build_cos_batch_from_queue` and the
  cap-aware exact drains pop via the fused select+pop pair
  `cos_queue_peek_min_bucket` + `cos_queue_pop_known_bucket` (#1763),
  both dispatching on `flow_fair()`. The MQFQ min-head-finish scan
  (`cos_queue_min_finish_bucket`, an O(N) linear scan over the active
  flow-bucket ring, N≈14 measured under iperf3 -P48) used to run twice
  per dequeue — once for the `cos_queue_front*` peek and again inside the
  `cos_queue_pop_front*` re-scan, with no queue mutation between — so the
  fused pair hands the peek's selected bucket straight to the pop and
  removes the redundant scan. A `target_bps == u64::MAX` no-cap fast path
  scans only `flow_bucket_head_finish_bytes`, skipping the dead
  `flow_bucket_observed_bps` load. Both levers are fairness-neutral by
  construction (byte-identical bucket selection and dequeue order),
  pinned by the `fused_diff_tests.rs` differential test against the
  retained `cos_queue_pop_front*` reference oracle. This also folds in
  the residual/best-effort
  queue-level → flow-level item from the #1731 research plan (its
  finding #7; NOT GitHub issue #7, which is an unrelated SNAT bug).
  Both scans (cap-aware and no-cap) gate their "chosen bucket" on
  `Option::is_none()`, NOT a bare `finish < best` compare against a
  `best = u64::MAX` seed (#hb166 T-7): a `flow_bucket_head_finish_bytes`
  that ever SATURATES to `u64::MAX` would otherwise be indistinguishable
  from the not-found sentinel and become a permanently unselectable
  active bucket whose packets never drain. This mirrors the R-8(b)/#4271
  vtime-sentinel clamp for the head-finish domain #4271 did not cover.
- Single-writer per FlowFairState. The owner worker that polls a
  binding is the same worker that owns the queue's
  `FlowFairState`; therefore `observed_bps` updates and reads do not
  need atomic synchronization.
- **Per-worker batch deques (#4973).** The non-exact shaped-TX path
  (`build_cos_batch_from_queue`, driven by `drain_shaped_tx` →
  `select_nonexact_cos_guarantee_batch_into` /
  `select_cos_surplus_batch_filtered`) no longer `VecDeque::new()`s a batch
  deque per selected batch. Two reusable deques (`cos_local_batch_scratch` /
  `cos_prepared_batch_scratch` on `WorkerCos`) are `mem::take`n into the built
  `CoSBatch`, then drained empty and stored back by the submit handler
  (`submit_local` / `submit_prepared`, via the now-returning
  `apply_cos_*_result` / `restore_cos_*_items`), retaining the ring-buffer
  allocation across drains — allocation-free after warmup. Each arm `clear()`s
  its scratch at entry so a store-back that left residue (a queue-torn-down
  early return returns the deque undrained) cannot leak into the next batch.
  Mirrors the #4972 `released_queue_leases_scratch` reuse pattern.
- **Cross-worker prepared-redirect copy pool (#6310).** The two
  cross-binding prepared-redirect sites in `cross_binding.rs`
  (`redirect_prepared_cos_request_to_owner{,_binding}`) must hand OWNED bytes
  to the owner worker: the source UMEM frame is recycled the instant the
  request is enqueued (`recycle_prepared_immediately_with_shared`) — freeing
  the scarce frame — and the owner consumes the bytes ASYNCHRONOUSLY on its
  own thread (it drains the per-binding `pending_tx` MPSC inbox, re-ingests
  into a CoS queue, and only copies the bytes into a UMEM TX frame at
  drain/settle). The copy is therefore genuinely required — a single shared
  scratch reused per packet would be overwritten before the owner reads it.
  Instead of a fresh `frame.to_vec()` per packet, the source worker checks a
  buffer out of a bounded per-worker THREAD-LOCAL free-list
  (`cos::redirect_pool`, `MAX_POOLED_BUFFERS`), copies the frame into it
  (retained capacity → allocation-free once warm), and moves it into the
  `TxRequest`. The pool is replenished at the exact-Local settle sites
  (`settle_exact_local_fifo_submission` /
  `settle_exact_local_scratch_submission_flow_fair`), which run on the owner
  worker AFTER the committed bytes were copied into a UMEM TX frame — so a
  recycled buffer is always dead. Thread-local pools are never shared across
  workers, so the cross-thread hand-off stays sound by Rust move semantics
  and the inbox single-consumer invariant alone (no locks, no aliasing, no
  UAF). Buffers migrate from redirect sources to owners; under the symmetric
  cross-worker CoS spread this targets (every worker both sources redirects
  and owns shaped queues), pools stay warm and the redirect copy is
  allocation-free after warmup. An asymmetric pattern just falls back to
  allocating on the depleted side and caps the buffer count on the other —
  bounded and self-healing, never incorrect. Same warmed-path allocation
  class as #4972 / #4973 / #5189; these two sites were simply never
  enumerated there.
- **A DEAD worker's V_min slot is vacated by the coordinator, not by the
  worker (#9367).** `PaddedVtimeSlot` has no TTL, generation or liveness
  input — `participating_v_min_snapshot` counts every non-sentinel peer slot
  and takes the MIN — and both worker-side `vacate()` sites (last flow bucket
  drained in `queue_ops/accounting.rs`, binding reset / HA demotion in
  `worker/cos/mod.rs`) are executed by the OWNING worker. A worker that exits
  by PANIC executes neither: the supervisor catches the unwind, sets `dead`,
  and lets the thread go, and the floor `Arc` survives because
  `coordinator/cos_leases.rs` reuses a floor while
  `f.slots.len() == num_workers`, which a panic does not change. The frozen
  `queue_vtime` then pins the cross-worker V_min while survivors' vtimes
  advance, `cos_queue_v_min_continue` never passes, and — because the
  suspension window is restored to full ONLY on a PASSING check — the window
  decays 1000 -> 64 and sticks: steady state is 8 throttled + 64 suspended,
  i.e. the fairness brake off for 64/72 = 88.9% of drain opportunities on
  that exact class. `Coordinator::vacate_worker_v_min_slots`, called from the
  same one-shot `holders_retired` CAS that reclaims NAT holder bits
  (`coordinator/status.rs`) and gated there on `atomics.dead`, releases the
  slot. It is then the only remaining writer — the owning thread has exited and
  nothing respawns it — so the single-writer contract still holds. The gate is
  not redundant with the sweep's own predicate: the sibling
  `retire_all_worker_holders` selects every id, live ones included, and runs
  while those workers are still publishing. #4254 (R-7) closed the sibling REJOIN
  door by seeding a rebuilt worker to the peer frontier; the never-returning
  door reaches the identical state and is not closed by that fix. A worker
  that STALLS without panicking is NOT covered: the poison is a property of
  the SLOT VALUE, nothing in the V_min reduction reads liveness, and the
  sweep selects on the panic `dead` flag.
- **V_min cadence persists across drain calls (#2624).** The
  cross-worker V_min sync (`cos_queue_v_min_continue` → the expensive
  `participating_v_min_snapshot` Acquire-load scan of every peer
  worker's slot) is rate-limited to the first proceeding pop and every
  `V_MIN_READ_CADENCE`-th pop thereafter. The cadence counter
  (`VMinQueueState::v_min_pop_count`) lives on the per-queue runtime, NOT
  as a `let mut = 0` local re-initialized at the top of each
  `drain_exact_*_to_scratch_flow_fair` call: under low/medium load the
  queue is drained in many small batches, so a per-call reset re-armed
  the mandatory first-pop full scan on EVERY drain, generating continuous
  cross-core cache-line ping-pong and defeating the cadence. It is
  counted over POPS THAT ACTUALLY PROCEED — a throttled drain breaks
  WITHOUT advancing it, so the next drain re-checks at the same cadence
  position (preserving the #941 hard-cap retry semantics). The counter
  advances ONLY on a CONFIRMED pop (#2646): the commit
  (`v_min_pop_count = candidate_pop_count`) is deferred past the gate
  to the point where the peek succeeds, the root/secondary budget and
  mirror-reserve checks pass, and `cos_queue_pop_known_bucket` actually
  removes the item. The gate (`cos_queue_v_min_continue`) is still
  evaluated at `candidate_pop_count` to drive the throttle / hard-cap
  accounting, but every POST-GATE no-pop exit (empty peek, wrong-variant
  head, budget miss, mirror-reserve miss, or a pop that returns None) now
  breaks without advancing the counter — so a head packet larger than the
  remaining budget no longer burns a cadence position while draining zero
  bytes (which would otherwise skip a mandatory/cadence peer snapshot and
  count a phantom pop in the bursty low-budget regime CoS targets). The
  gate-throttle path is unchanged (it breaks before the commit, as in
  #2624), so the #941 hard-cap retry semantics are unaffected. Both
  flow-fair drains (Local + Prepared) for a queue run on that queue's
  single owner worker and share the one counter, so it is a plain `u32`
  with no atomics — the same single-writer model as the sibling
  `consecutive_v_min_skips` / `v_min_suspended_remaining` fields.
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
- **Pop-snapshot stack is cleared at batch start on BOTH drain paths
  (#785 exact, #3968 non-exact).** Each MQFQ pop pushes a rollback
  snapshot onto the per-queue `FlowFairState::pop_snapshot_stack`
  (bounded to `TX_BATCH_SIZE`); a partial-commit `cos_queue_push_front`
  pops one per RETRIED item, but a whole-batch commit consumes none and
  leaves the batch's snapshots resident. `cos_queue_push_back` clears
  them on the next enqueue, but a saturated queue is drained across
  consecutive batches with no intervening enqueue. So every batch build
  clears the stack at entry: the exact drains
  (`drain_exact_{local,prepared}_items_to_scratch_flow_fair`) and the
  non-exact `build_cos_batch_from_queue`. Any snapshots resident at
  build entry belong to an already-submitted batch and are stale — the
  submit and its synchronous rollback completed before the next build.
- Scheduler-map queues without a positive explicit scheduler
  `transmit-rate` are residual-only under a shaped root. They keep an
  effective rate for burst sizing and surplus weight, but
  `queue_service` skips them in guarantee selectors via
  `queue.config.guarantee_enabled == false`.
- Residual-only / non-exact queues keep their explicit guarantee
  service, but their surplus service is bounded while exact queues
  have demand on the same shaped interface. The bound is the residual
  root rate after reserving each backlogged exact queue's configured
  guarantee rate once. Cross-binding demand is imported through
  `SharedCoSExactBacklog` as an exact-queue mask, not a per-worker
  rate, so one shared exact queue does not multiply its reservation by
  the number of workers. Shared interfaces also use a shared residual
  token bucket for non-exact surplus; private/local fallbacks use the
  per-root residual bucket. Exact queues that explicitly enable
  `surplus-sharing` remain eligible for surplus service outside the
  non-exact residual budget.
- **Shared queue-lease conservation for non-exact lease-metered queues
  (#4265 / #5156).** A non-exact GUARANTEED queue whose configured rate
  trips `COS_SHARED_EXACT_MIN_RATE_BYTES` runs the sharded `shared_exact`
  execution policy: it drains locally on EVERY worker, so the coordinator
  attaches a shared legacy `SharedCoSQueueLease` and its class-wide
  admission is metered through that lease instead of a private per-worker
  bucket. `CoSQueueConfig::is_shared_lease_metered()` (in `types/cos.rs`)
  is the SINGLE source of truth for "this non-exact queue is
  lease-metered" — the coordinator
  (`build_shared_cos_queue_leases_reusing_existing`) and the runtime
  builder (`build_cos_interface_runtime`) both gate on it, so the lease's
  init charge and teardown give-back stay symmetric. The conservation
  invariant: every byte the queue's `hot.tokens` ever holds is acquired
  through — and returned to — the shared lease's `outstanding` word.
  Concretely such a queue starts at 0 local tokens (like an exact queue,
  NOT pre-filled `buffer_bytes`), acquires its bank through
  `maybe_top_up_cos_queue_lease` → `acquire_via_lease`, gives an emptied
  bank back at runtime in `refresh_cos_interface_activity`, and gives its
  residual bank back at worker exit / binding reset / lease-set swap in
  `release_all_cos_queue_leases`. Both give-back sites gate the
  `core::mem::take(&mut queue.hot.tokens)` ITSELF on lease presence
  (`shared_queue_lease.is_some()`), NOT on `queue.config.exact`, so a
  truly un-leased single-owner queue (exact or non-exact) keeps its
  private per-worker burst — there is nowhere to give it back. (#6272:
  the teardown site's take was originally unconditional — only its credit
  was lease-gated — so an un-leased non-exact queue's banked burst was
  wrongly zeroed on a lease-set swap; the take is now lease-gated to
  mirror the runtime `refresh_cos_interface_activity` R-5(a) path.)
  `release_unused_v8` reduces to the legacy `release_unused` for a legacy
  (v8=None) lease.
- `COS_MIN_BURST_BYTES` (64 × MTU) is canonically owned by
  `token_bucket.rs`; siblings import it via the `cos/mod.rs`
  re-export.
- Scheduler `buffer-size <n>%` is resolved before runtime queue creation
  as `<n>%` of the interface CoS burst pool. The pool is the explicit
  `class-of-service interfaces ... shaping-rate burst-size` value when
  configured, otherwise the same `default_cos_burst_bytes` root-burst
  fallback used by the shaper. The legacy `buffer_size_bytes` protocol
  field still wins when present; `buffer_size_percent` is additive for
  #1336 compatibility. Go-side config validation rejects per-interface
  scheduler-map percent totals above 100%, so Rust only receives
  already-admitted percent allocations. xpf rejects `0%` before the
  snapshot because zero is the additive field's legacy absent value.
