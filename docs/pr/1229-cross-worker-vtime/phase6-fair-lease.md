# #1229 Phase 6: per-worker fair lease (weighted share)

**Status:** DRAFT v1 — pending adversarial plan review

## Issue framing

The cross-worker fairness drive against #1229 shipped Phases 1-4 in PR
#1230 (cap-aware MQFQ + monotonic per-bucket TX rate tracking). The
shipped code does not even out per-flow throughput on the user's
iperf-e (16G EXACT) workload — empirical samples show 4-6x spread
between fastest and slowest flows.

Codex diagnostic [task-mowgluqr-1e032q] verified on the running cluster
identified the actual structural cause:

`SharedCoSQueueLease` in `userspace-dp/src/afxdp/types/shared_cos_lease.rs`
is a **greedy aggregate token bucket**, not a fair per-worker
allocator. The CAS loop at `shared_cos_lease_acquire()` (lines 258-290)
has no worker identity, no per-worker share, no fairness state. It
grants `min(requested, available_tokens, lease_headroom)` to whoever
asks first. When demand exceeds shaper rate, faster requesters win
more lease.

Empirical CPU verification on the running iperf-e workload:
- iperf3 reports firewall total CPU at 154.4% / 600% = ~26% load.
- Workers are NOT CPU-bound. They're lease-starved.
- This means a fair lease allocation will not lose aggregate throughput
  on this workload — workers have headroom to consume their share.

## Honest scope/value framing

Phase 6 replaces the greedy shared lease with a weighted per-worker
share:

```
worker_share_bps_i = (worker_i.active_flow_buckets / total_active_flow_buckets) * class_rate_bps
```

Predicted iperf-e outcome (12 flows on 4 active workers, 16G shaper):

| Worker | flows | share predicted | currently | expected per-flow |
|--------|-------|-----------------|-----------|-------------------|
| A      | 4     | 4/12 × 16G = 5.33G | 2.92G | 1.33G |
| B      | 3     | 3/12 × 16G = 4.00G | 2.58G | 1.33G |
| D      | 4     | 4/12 × 16G = 5.33G | 6.40G | 1.33G |
| E      | 1     | 1/12 × 16G = 1.33G | 3.19G | 1.33G |

Aggregate stays at 16G shaper rate (no throughput loss).
Per-flow CoV → near-zero on shaper-bound workloads.

**If reviewers conclude this mechanism is unsound, has hidden
performance regressions on saturated workloads, or contradicts a
fundamental architectural constraint, PLAN-KILL is an acceptable
verdict.**

Specific reasons PLAN-KILL might be the right call:
- If on saturated workloads (iperf-c push at full 22.7G), the
  per-worker share starves a worker whose flows could otherwise
  consume more, dropping aggregate.
- If the `total_active_flow_buckets` denominator can't be computed
  cheaply enough on the hot path (per-acquire atomic read of N
  per-worker counters has unacceptable cost).
- If the convergence properties under flow churn (flows starting
  and stopping) cause oscillation or starvation.

## What's already shipped / partially batched

- **Phase 1+2** (commit 2975b394): FlowFairState gained 4 monotonic
  per-bucket fields: `flow_bucket_tx_bytes`, `flow_bucket_observed_bps`,
  `flow_bucket_last_tx_ns`, `flow_bucket_pending_bytes`. Initialized
  in `FlowFairState::new`. ~860 KB total.
- **Phase 3** (commit a95888c1): `account_flow_bucket_tx` wired into
  4 flow-fair commit paths (Local + Prepared, exact + plain). Now-ns
  sampled once per batch.
- **Phase 4** (commit de5dd54c): `cos_queue_min_finish_bucket` takes
  `target_bps`; `cos_queue_front_with_cap` and
  `cos_queue_pop_front_with_cap` are cap-aware variants. Drain paths
  compute `target_bps = transmit_rate / active_flow_buckets` once per
  batch and pass through.
- **Phase 5** (commit fbdcac21+fecc5d09): cluster smoke documented
  the shipped code's effect on iperf-e (modest CoV reduction; not
  the goal).

Phase 6 keeps Phases 1-4 as supporting infra. The per-worker fair
lease enforces inter-worker fairness; Phase 4's cap-aware MQFQ
selector continues to enforce intra-worker fairness within the
share that's been granted to each worker.

## Concrete design

### 6.1 Active-flow-buckets accounting (per worker)

Each worker already maintains `active_flow_buckets: u32` per
CoSQueueRuntime as part of FlowFairState. This count tracks how many
distinct flow buckets currently have packets queued.

For Phase 6, sum these across all CoSQueueRuntimes on a single worker
to get the worker's class-wide active-flow-bucket count. Per worker,
per class.

We surface this via a per-worker shared atomic stored in a new struct
field on the SharedCoSQueueLease side:

```rust
pub(in crate::afxdp) struct SharedCoSQueueLease {
    config: SharedCoSLeaseConfig,
    state: SharedCoSLeaseState,
    // NEW: per-worker active-flow-bucket counters.
    // Length = active_shards (set at construction). Each worker
    // updates ONLY its own slot via Relaxed store on transitions
    // (0->1 / 1->0 of its own active_flow_buckets count for any
    // queue mapped to this lease). Reads sum all slots — Relaxed
    // is fine because the denominator is intrinsically a hint
    // (flow churn races with grant decisions are bounded by the
    // refill cadence, ~200us).
    worker_active_flow_buckets: Box<[AtomicU32]>,
}
```

Worker IDs in `[0, active_shards)`. Each worker has a stable ID
already (from neighbor.rs:503 worker pinning).

### 6.2 Acquire path

Replace the existing `shared_cos_lease_acquire(config, state, now_ns,
requested)` with a per-worker variant that takes the worker ID:

```rust
fn shared_cos_lease_acquire_for_worker(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    worker_active_flow_buckets: &[AtomicU32],
    worker_id: usize,
    now_ns: u64,
    requested: u64,
) -> u64 {
    if requested == 0 {
        return 0;
    }
    refill_shared_cos_lease_state(config, state, now_ns);

    // Compute this worker's share of available tokens.
    // Sum is recomputed per-acquire — bounded by `active_shards`
    // (typically 6 on this hardware), so this is ~6 atomic loads
    // per acquire. Acquires happen at lease-refill cadence
    // (~200us), not per packet, so cost is amortized.
    let my_count = worker_active_flow_buckets[worker_id]
        .load(Ordering::Relaxed) as u64;
    if my_count == 0 {
        // Worker has no flow buckets active on this lease — no
        // share. Fall back to legacy greedy behavior so non-flow-
        // fair traffic (single packets, control) still flows.
        // Bounded above by available_tokens like the original.
        return shared_cos_lease_acquire_legacy(config, state, requested);
    }
    let total: u64 = worker_active_flow_buckets
        .iter()
        .map(|c| c.load(Ordering::Relaxed) as u64)
        .sum();
    let total = total.max(my_count); // total>=my_count always (we
                                     // just observed my_count)

    loop {
        let credits = state.credits.load(Ordering::Acquire);
        let (available_tokens, outstanding_leased_tokens) =
            unpack_shared_cos_lease_credits(credits);
        let lease_headroom = config
            .max_total_leased
            .saturating_sub(outstanding_leased_tokens);

        // Worker's fair share of currently-available tokens.
        // Floor-divides so total share <= available; remainder
        // (up to active_shards-1 bytes) stays in the bucket for
        // the next acquire.
        let my_share = (available_tokens as u128)
            .saturating_mul(my_count as u128)
            .checked_div(total as u128)
            .unwrap_or(0) as u64;

        let granted = requested
            .min(my_share)
            .min(lease_headroom);
        if granted == 0 {
            return 0;
        }
        let new_credits = pack_shared_cos_lease_credits(
            available_tokens.saturating_sub(granted),
            outstanding_leased_tokens.saturating_add(granted),
        );
        if state
            .credits
            .compare_exchange_weak(credits, new_credits,
                Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return granted;
        }
    }
}
```

**Hot-path reasoning**:
- Lease acquires happen at refill cadence (200us), not per packet.
- ~6 Relaxed loads + 1 div per acquire. At 5K acquires/sec/worker
  = 30K loads/sec total. Trivial.
- The `total >= my_count` invariant is preserved by ordering:
  we read my_count first, then sum. If another worker decremented
  mid-sum, total could undercount, but never below my_count's
  contribution.

### 6.3 Update path

Workers update their slot when their per-class active_flow_buckets
count changes:

```rust
// In FlowFairState transitions where active_flow_buckets changes:
//   - Bucket 0->1 (first packet enters bucket): increment by 1
//   - Bucket 1->0 (bucket fully drained): decrement by 1
//
// `lease.worker_active_flow_buckets[worker_id].fetch_add(1, Relaxed)`
// `lease.worker_active_flow_buckets[worker_id].fetch_sub(1, Relaxed)`
```

These transitions already exist in `cos/queue_ops/accounting.rs`
(`account_cos_queue_flow_enqueue` / `account_cos_queue_flow_dequeue`)
and `cos/queue_ops/pop.rs` (drain-empty path). Phase 6 wires the
shared atomic update into those existing transition points.

### 6.4 Lease backreference

Each CoSQueueRuntime needs a way to find its SharedCoSQueueLease so
the accounting transitions can update the shared counter. The lease
is owned by the per-class root state (one lease per class); the
queue runtime already has access to its class config. Add a back
pointer or pass-through.

The existing flow-fair maintenance in accounting.rs takes
`&mut CoSQueueRuntime`. We extend the call sites that wrap it
(in tx/dispatch, settle paths, drain paths) to also receive the
lease handle and call the shared atomic update from there. No
queue-internal pointer added.

### 6.5 Worker ID resolution

Workers are pinned 1:1 to CPUs and have a stable `worker_id` known
at construction time. The WorkerRuntime already has `worker_id`.
The lease-acquire call site in `cos/token_bucket.rs:64` is inside
worker context, so threading the worker_id through is mechanical.

### 6.6 active_shards == worker count alignment

`SharedCoSLeaseConfig.active_shards` is currently used to size
`max_total_leased` ceiling (line 235). It defaults to the number
of bindings, which == number of workers. Phase 6 reuses this for
the worker_active_flow_buckets array length. No new construction-
time parameter needed.

## Public API preservation

- `SharedCoSQueueLease::new` signature unchanged externally; adds
  internal `worker_active_flow_buckets: Box<[AtomicU32]>` of length
  `active_shards`, all zero.
- `SharedCoSQueueLease::acquire` gains a `worker_id: usize` parameter.
  Migration: every existing caller site in `cos/token_bucket.rs`
  receives the worker_id from the surrounding worker context.
- `SharedCoSQueueLease::consume` (release-side) unchanged.
- No new public types added.

Old `shared_cos_lease_acquire` is retained as
`shared_cos_lease_acquire_legacy` for the fallback case where a
worker has zero active flow buckets on a class (control/single-
packet traffic to a class with no per-flow state). Caller selects
based on `my_count == 0`.

## Hidden invariants the change must preserve

1. **Aggregate cap unchanged**: The class shaper rate (16G EXACT
   on iperf-e, 25G EXACT on iperf-c) must remain enforced exactly.
   Phase 6 redistributes share of the 16G; it does not change the
   16G total. Preserved by leaving `available_tokens` accounting
   unchanged — only the grant per-call is fairer.

2. **Side-effect ordering**: The CAS loop on `state.credits` is
   unchanged. Only the per-call `granted` value changes (bounded
   above by the worker's fair share). Concurrent acquires from
   different workers race the same CAS but each computes its own
   share, so they don't conflict semantically.

3. **HA sync portability**: `SharedCoSQueueLease` is per-process,
   not synced. The new `worker_active_flow_buckets` field is
   construction-local. No HA wire format change.

4. **Stale-handle hazards**: `worker_id` is a stable index into
   the `worker_active_flow_buckets` slice. The lease's slice
   length is fixed at construction. No reallocation.

5. **Lifetime / borrow-checker shape**: `worker_active_flow_buckets`
   is a `Box<[AtomicU32]>` owned by the lease. Workers hold an
   `Arc<SharedCoSQueueLease>` (existing pattern); they can call
   `lease.worker_active_flow_buckets[worker_id].fetch_add(...)`
   via the Arc deref. No new lifetime story.

6. **Token conservation**: `available_tokens` is decremented exactly
   once per granted byte. Outstanding leased tokens released via
   `consume()` unchanged. Floor-division of `my_share` leaves a
   remainder of at most `active_shards - 1` bytes per refill — bounded.

7. **Convergence under flow churn**: Flow start/stop transitions
   change `worker_active_flow_buckets` mid-computation. Reads are
   Relaxed; the floor-divide is monotone in numerator/denom. Worst
   case: a worker over-grants for one acquire (200us) then
   self-corrects on next refill. Bounded transient.

## Risk assessment

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | Aggregate rate unchanged; only per-worker grant ratio changes. Legacy fallback preserves original behavior for non-flow-fair traffic. |
| Lifetime / borrow-checker | LOW | `Box<[AtomicU32]>` is owned by the lease; workers access via existing `Arc<lease>` deref. No new pointer story. |
| Performance regression | MED | Per-acquire cost goes from 1 atomic load to ~6+1div+1mul. At 5K acquires/sec/worker, this is ~30K extra cycles/sec/worker — negligible. Risk: if acquire rate spikes (very small lease grants), could become measurable. Mitigate: profile under saturation, set alarm if cost > 0.1% of cycles. |
| Architectural mismatch | MED | The shared lease is itself a sound abstraction; weighted-share is a known fair-queueing pattern. Risk: if a customer workload has many tiny flow buckets that churn rapidly, the denominator becomes noisy and per-worker share oscillates. Mitigate: per-call snapshot semantics (read once, divide once) prevents in-call inconsistency; cross-call hysteresis is the next-stage problem if observed. |

## Test plan

- Cargo build clean (TMPDIR=/dev/shm).
- Cargo test --release: 1065+ tests must continue to pass.
- New tests in `types/shared_cos_lease_tests.rs` (or sibling):
  - Two-worker fair share: each gets ~50% under equal demand.
  - Asymmetric flow counts: 4 flows worker A, 1 flow worker B → A
    gets 80%, B gets 20%.
  - Zero-active-flows worker hits legacy fallback path.
  - Worker that doesn't request still has its share preserved (not
    re-stolen on next acquire).
  - Flow churn mid-acquire: invariant holds (no underflow, no over-
    grant).
- 5x flake check on the most affected named test
  (`shared_cos_lease_per_worker_fairness_basic`).
- Go suite: 30 packages pass.
- Cluster smoke matrix on loss userspace cluster (CoS disabled
  baseline + CoS enabled per-class 5201-5206, v4+v6, push+reverse).
- Targeted iperf-e measurement: confirm per-flow CoV drops from
  ~60% to <10% on the canonical reproducer.
- Targeted iperf-c saturation measurement: confirm aggregate stays
  at the recipe-doc's 22.7G ceiling, observed_cov stays at the
  ~21% sender-side floor (not regressed).

## Out of scope (explicitly)

- **Cross-binding redirect**: the lease still applies per-binding.
  AF_XDP UMEM ownership constraints unchanged.
- **Hierarchical CoS** (parent/child class shares): Phase 6 is per-
  class fair lease only.
- **Workload-aware gate switching**: the share formula is static
  per acquire. No adaptive damping.
- **HA sync of the active-flow-bucket counter**: not needed; per-
  process state.

## Open questions for adversarial review

1. **Cost of per-acquire denom recompute**: ~6 atomic loads + 1 u128
   div per acquire. Acquires happen at ~200us cadence. Is this
   measurable on the hot path? If a profile shows it as a hot fn
   could a per-refill-cached denominator (refresh once per refill)
   be safe enough?

2. **u128 division on ARM/x86**: the share formula uses `(u64 *
   u64) / u64` via u128. Compiles to a single 64x64->128 mul + 128/64
   div on x86-64. On older platforms the lib call may be slower.
   Should we floor `my_count` and `total` to u32 and use u64 math
   only?

3. **Floor-division remainder**: each call leaves up to
   `active_shards-1` bytes unallocated per refill. Over 5K
   acquires/sec × 5 leftover-bytes = ~25 KB/sec leak, capped by
   the next refill anyway. Acceptable, or do we need a more
   complex remainder distribution?

4. **Worker transition serialization**: `fetch_add(1, Relaxed)` on
   active_flow_buckets transition is unsynchronized with denom
   reads on other workers. The acquire-path read of `total` may
   miss in-flight transitions. Worst case: granted is too big for
   one acquire window. Bounded by refill cadence. Is this what
   you'd expect, or does it need stronger ordering?

5. **Architectural mismatch with #1211 (PLAN-KILLED)**: #1211
   was a "race-safe AFD" that died because PR #1220's empirical
   PASS made it solving a non-existent problem. Phase 6 is *not*
   AFD — it's per-worker share, not per-flow ECN/drop overlay.
   Does this mechanism risk recapitulating #1211's mistakes, or
   is the design distinction sharp enough?

6. **Sender-side TCP unfairness floor**: the recipe doc shows
   sender-side TCP head-start adds ~25% CoV. After Phase 6
   evens the dataplane share, will the sender's ~25% TCP head-
   start still dominate, leaving observed_cov stuck near 25%?
   (If so, Phase 6's marginal value is reduced.)

7. **`active_shards` vs actual worker count**: Currently
   `active_shards` defaults to number of bindings. If multiple
   bindings run on the same worker (or vice versa), the worker_id
   index could collide or be sparse. Need to verify
   active_shards == max_worker_id + 1 always holds, or
   refactor to a HashMap<worker_id, AtomicU32>.

8. **Effect on iperf-c saturated**: At 22.7G saturated, all
   workers ARE CPU-bound (recipe doc). Per-worker fair share
   becomes per-CPU-fair-share. The fast workers get less; the
   slow workers can't use more. Aggregate could drop. Acceptable?
   PLAN-KILL if drop > 2%.
