# #1229 Phase 6: per-worker fair lease (weighted share)

**Status:** v1 PLAN-KILLED 2026-05-07 — convergent kill from Codex
([task-mowh7owm-4n7xbp](#)) and Gemini Pro 3
([task-mowh8abt-rwy571](#)). Pursuing v2 with redesigned mechanism.

## v1 KILL summary (preserved for reference)

Both reviewers independently identified the same architectural defect:
the formula `granted = available_tokens × my_count / total` allocates
share of **residual balance**, not share of **arrival rate**. This
preserves first-acquirer advantage:

- Codex geometric proof: with [4,3,4,1] flows acquiring in order,
  steady-state limit is ~48% / 24% / 24% / 4%, not the claimed
  5.33/4.00/5.33/1.33.
- Gemini polling-rate proof: worker A at 1ms acquire vs B at 10ms,
  equal share → A gets 90%, B gets 10%.

Other convergent fatal findings (preserved as v2 input requirements):
- `active_shards` is per-interface bound count; `worker_id` is global
  daemon index. Direct `arr[worker_id]` panics on sparse bindings.
- `my_count == 0` legacy fallback is a fairness bypass during
  accounting transitions, lease replacement, worker restart.
- iperf-c saturation: throttling the 1-flow worker (running ~4 Gbps
  in [6,5,1] saturated config per recipe doc) to 1/12 share strips
  ~2 Gbps that CPU-bound peer workers cannot absorb. Aggregate drops
  from 22.7G — violates "no throughput loss" claim.
- `SharedCoSRootLease::acquire` shares the same function. v1 missed
  this bypass path.

The redesign direction (Codex verbatim): "A replacement plan needs
per-worker credits, dense worker-slot mapping, no greedy zero-count
fallback, counter rehydration on lease replacement, and an explicit
root-lease story."

v2 below redrafts against these constraints.

---

## Status (v2)

**Status:** v2 PLAN-KILLED 2026-05-07 — second consecutive convergent
kill from Codex ([task-mowhk86b-m1hjem](#)) and Gemini Pro 3
([task-mowhkc6j-wx5jmq](#)).

## v2 KILL summary

Convergent fatal findings (both reviewers):

1. **Polling skew still wins**: `max_reserve = 2×lease_bytes` is too
   narrow. Slow-polling worker spills accumulated share to
   redistribution pool; fast poller steals from there. v1 polling-rate
   problem reintroduced with extra steps.
2. **Aggregate cap broken**: per-worker pools grant tokens
   independently of `max_total_leased`; cap is checked AFTER grant
   via `bump_outstanding_leased`. Cap violation possible.
3. **Token leak**: redistribution pool is unbounded. CPU-bound peers
   cause indefinite accumulation. Later, when CPU frees, workers
   drain at burst rate violating the shaper (Gemini's "infinite
   accumulation" finding).
4. **Sparse-worker-id panic**: `last_planned_workers` (Codex F4) is
   `workers.len()`, not `max(worker_id)+1`. Sparse IDs starve
   permanently when bounds-checked. Also `last_planned_workers`
   mutates at runtime via reconcile passes (`coordinator/mod.rs:553`).
5. **Surplus-sharing / root / transparent-rate bypasses** (Codex F6):
   scope as written ("flow-fair queues only call v2") is too broad —
   v2 only applies to Guarantee-phase exact queues; other paths
   already bypass queue lease and v2 doesn't cover them.
6. **`my_count == 0` fallback** still effectively greedy: workers
   with no per-worker credits unconditionally drain the
   redistribution pool, defeating fairness.
7. **Counter rehydration race**: explicit init in
   `enable_test_flow_fair` doesn't cover production
   queue-lease-Arc replacement at `worker/mod.rs:805`.

Codex-only: epoch CAS publish-before-distribute stall window if
winner is preempted.

Gemini-only: `max_reserve = 2×lease_bytes` per-worker × N workers =
2N×lease_bytes total → silently breaks aggregate burst cap by 2N.
TCP sender-side floor (~25%) on iperf-c saturation will dominate
even after dataplane fairness is fixed → complexity unjustified by
win.

## Architectural insight: the tri-lemma

The v1 → v2 progression revealed a structural tension:

| Property | v1 | v2 |
|----------|----|----|
| Aggregate cap respected | yes | NO |
| Per-worker fairness | NO (residual-balance) | NO (max_reserve cap) |
| Work conservation | yes (greedy = wins) | partial (bounded spill) |

Achieving all three (per-worker fair share + strict aggregate cap +
work-conserving redistribution) is the hard tri-lemma. The classical
solution is **hierarchical token bucket** (HFSC / CBQ): parent rate
limiter + per-class child shares + borrow chains across the
hierarchy. That's a multi-week architectural rebuild at the dataplane
layer — and #1211 went 8 Codex + 3 Gemini rounds before PLAN-KILL on
a similar-scope rework.

## Status

**STOPPED — pending user decision.**

Per the project's triple-review methodology, two convergent
PLAN-KILLs is a STOP signal. The fairness drive is at the same
architectural inflection that closed #1211: AF_XDP UMEM ownership +
per-worker queue lease + aggregate cap form a tri-lemma that's not
solvable with stateless fractional caps or bounded credit pools.

Options for the user to choose:

1. **Accept the structural ceiling.** Recipe doc empirically shows
   sub-saturation iperf-e at 0.6% CoV with `-b 1.5G` (workload-side
   rate cap). Saturation has 8-21% structural CoV from sender-side
   TCP unfairness + inter-worker CPU asymmetry; firewall is at its
   hardware limit. PR #1230 ships Phases 1-5 as useful infra
   (cap-aware MQFQ + monotonic per-bucket TX-rate tracking) that
   benefits the sub-saturation case.

2. **Hierarchical token bucket (option A)**: multi-week rebuild,
   against #1211's PLAN-KILL precedent. High risk that another
   8+3 round review converges on the same kill.

3. **Different direction entirely** (option C): time-window sharing
   instead of token pools — per-worker sliding-window quota with
   global virtual-time; no token accumulation. Not yet explored;
   would need fresh plan + reviewer rounds.

## v2 redesign: per-worker credits + work-conserving redistribution

The v1 formula was a stateless fractional cap on a shrinking shared
bucket; that preserves first-acquirer advantage. v2 implements **real
per-worker credit pools** with **weighted refill** and a **work-
conserving redistribution pool** to preserve aggregate throughput on
saturated CPU-bound workloads.

### v2.1 State layout

```rust
pub(in crate::afxdp) struct SharedCoSQueueLease {
    config: SharedCoSLeaseConfig,
    // Existing shared aggregate state — stays for legacy callers
    // (e.g., SharedCoSRootLease takes a separate code path that does
    // NOT use per-worker credits). Continued use for root traffic.
    state: SharedCoSLeaseState,

    // NEW v2: dense per-worker credit pools, indexed by worker_id.
    // Length = max_worker_id + 1 (NOT active_shards). Sized at lease
    // construction from the daemon's worker count, queried via
    // `coordinator/mod.rs::last_planned_workers` (existing source of
    // truth for the per-worker indexing space, also used by V_min
    // floor sizing). Sparse interface bindings leave gaps; gaps stay
    // at 0 forever (workers not bound to this lease never request).
    worker_credits: Box<[AtomicU64]>,

    // NEW v2: per-worker active flow bucket count, indexed by
    // worker_id. Same length as worker_credits.
    worker_active_flow_buckets: Box<[AtomicU32]>,

    // NEW v2: redistribution pool — surplus from CPU-bound workers
    // flows here at refill, available to lease-starved workers.
    redistribution_pool: AtomicU64,

    // NEW v2: per-refill epoch counter — used for credit reset
    // boundary detection.
    refill_epoch: AtomicU64,
}
```

### v2.2 Refill path (epoch boundary)

`refill_shared_cos_lease_state` is called on each `acquire`. v2
augments it with a per-worker credit refresh that runs at most once
per refill epoch (~200 us under default config):

```rust
fn refill_shared_cos_lease_state_v2(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    worker_credits: &[AtomicU64],
    worker_active_flow_buckets: &[AtomicU32],
    redistribution_pool: &AtomicU64,
    refill_epoch: &AtomicU64,
    now_ns: u64,
) {
    // Existing aggregate-bucket refill stays — refill_amount is
    // computed from rate × elapsed.
    let refill_amount = compute_refill_amount(config, state, now_ns);
    if refill_amount == 0 {
        return;
    }
    // Atomic CAS to advance epoch. Only one worker thread runs the
    // distribution path per epoch; others see the new epoch and skip.
    let old_epoch = refill_epoch.load(Ordering::Acquire);
    let new_epoch = old_epoch + 1;
    if refill_epoch
        .compare_exchange_weak(old_epoch, new_epoch,
            Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return; // another worker won the epoch race; they distribute
    }

    // Compute total active flow buckets across workers.
    let total_count: u64 = worker_active_flow_buckets
        .iter()
        .map(|c| c.load(Ordering::Relaxed) as u64)
        .sum();
    if total_count == 0 {
        // No flow-fair traffic on any worker. Drop refill into
        // redistribution pool — root lease and control traffic
        // can pull from there if needed.
        redistribution_pool.fetch_add(refill_amount, Ordering::AcqRel);
        return;
    }

    // Distribute refill_amount proportionally to per-worker counts.
    // Surplus from CPU-bound workers (credits > MAX_RESERVE) spills
    // into redistribution_pool — work-conserving.
    let max_reserve = config.lease_bytes.saturating_mul(2);
    let mut remainder = refill_amount;
    for (worker_id, count_atom) in worker_active_flow_buckets.iter().enumerate() {
        let my_count = count_atom.load(Ordering::Relaxed) as u64;
        if my_count == 0 {
            continue; // worker has no flow-fair demand
        }
        let my_share = (refill_amount as u128)
            .saturating_mul(my_count as u128)
            .checked_div(total_count as u128)
            .unwrap_or(0) as u64;
        let credits_atom = &worker_credits[worker_id];
        let new_credits = credits_atom
            .fetch_add(my_share, Ordering::AcqRel)
            .saturating_add(my_share);
        // Surplus spill: if a worker accumulated > max_reserve, it
        // is CPU-bound (not consuming as fast as it's earning).
        // Trim its credits back to max_reserve and spill the excess.
        if new_credits > max_reserve {
            let excess = new_credits - max_reserve;
            // Try to subtract excess; if a concurrent acquire
            // dropped credits below max_reserve, abandon the spill.
            if credits_atom
                .compare_exchange(new_credits, max_reserve,
                    Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                redistribution_pool.fetch_add(excess, Ordering::AcqRel);
            }
        }
        remainder = remainder.saturating_sub(my_share);
    }
    // Floor-division remainder spills to redistribution pool —
    // bounded by total_count - 1 bytes per refill (~6 bytes max).
    if remainder > 0 {
        redistribution_pool.fetch_add(remainder, Ordering::AcqRel);
    }
}
```

### v2.3 Acquire path (per-worker first, then redistribution)

```rust
fn shared_cos_lease_acquire_for_worker_v2(
    config: SharedCoSLeaseConfig,
    state: &SharedCoSLeaseState,
    worker_credits: &[AtomicU64],
    redistribution_pool: &AtomicU64,
    worker_id: usize,
    now_ns: u64,
    requested: u64,
) -> u64 {
    if requested == 0 {
        return 0;
    }
    // Refill (idempotent within an epoch).
    refill_shared_cos_lease_state_v2(/* ... */, now_ns);

    // Bounds check: out-of-range worker_id is a bug — panic in
    // debug, fall to legacy in release for safety.
    if worker_id >= worker_credits.len() {
        debug_assert!(false, "worker_id out of range: {}", worker_id);
        return 0;
    }

    // First: drain own credits.
    let my_credits = &worker_credits[worker_id];
    let mut total_granted: u64 = 0;
    let mut still_needed = requested;
    loop {
        let curr = my_credits.load(Ordering::Acquire);
        if curr == 0 || still_needed == 0 {
            break;
        }
        let take = still_needed.min(curr);
        if my_credits
            .compare_exchange_weak(curr, curr - take,
                Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            total_granted += take;
            still_needed -= take;
        }
    }

    // If still need more, dip into redistribution pool. This is the
    // work-conserving step: CPU-bound peers' surplus flows to the
    // workers that can use it.
    while still_needed > 0 {
        let curr = redistribution_pool.load(Ordering::Acquire);
        if curr == 0 {
            break;
        }
        let take = still_needed.min(curr);
        if redistribution_pool
            .compare_exchange_weak(curr, curr - take,
                Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            total_granted += take;
            still_needed -= take;
        }
    }

    // Update outstanding leased tokens for cap enforcement.
    if total_granted > 0 {
        // The shared aggregate state still tracks total outstanding
        // tokens against max_total_leased — this preserves the
        // existing cap and the root-lease compatibility.
        bump_outstanding_leased(state, total_granted);
    }
    total_granted
}
```

### v2.4 Root lease — no change

`SharedCoSRootLease::acquire` and the existing
`shared_cos_lease_acquire` (now renamed `_legacy`) stay unchanged.
Root lease pre-empts queue lease for control traffic — it acquires
from the shared bucket directly, bypassing per-worker credits. v1's
"my_count == 0 fallback" is removed entirely; flow-fair queues NEVER
fall through to legacy. Only `SharedCoSRootLease` uses the legacy
greedy path.

### v2.5 Counter rehydration on lease replacement

When a CoSQueueRuntime promotes from non-flow-fair to flow-fair (or
the lease is recreated due to config change), the bucket transition
events that would re-populate `worker_active_flow_buckets` may be
missed. v2 adds an explicit init step in
`enable_test_flow_fair`/`disable_test_flow_fair` and the production
promotion path: snapshot the queue's current bucket population and
emit the corresponding fetch_add/fetch_sub on the lease's worker
slot. This eliminates the stale-counter race that v1's legacy
fallback was masking.

### v2.6 max_worker_id sizing

`SharedCoSQueueLease::new` accepts `max_worker_id: usize` from the
constructor (passed by the coordinator from `last_planned_workers`,
the existing per-worker indexing source — coordinator/mod.rs:1040
already uses this for V_min floor sizing). `worker_credits.len()
== worker_active_flow_buckets.len() == max_worker_id + 1`. Sparse
bindings leave gaps; gaps stay at 0 (no fill, no leak).

## Public API preservation (v2)

- `SharedCoSQueueLease::new` signature CHANGES: gains
  `max_worker_id: usize` parameter. Caller in coordinator/mod.rs is
  the only construction site; trivial migration.
- `SharedCoSQueueLease::acquire` signature CHANGES: gains
  `worker_id: usize` parameter. Caller in `cos/token_bucket.rs:64`
  is the only flow-fair acquisition site; passes
  `runtime.worker_id`.
- `SharedCoSQueueLease::consume` (release-side) unchanged.
- `SharedCoSRootLease::acquire` unchanged.
- New private helpers: `refill_shared_cos_lease_state_v2`,
  `shared_cos_lease_acquire_for_worker_v2`. Old `_legacy` retained
  only for root lease internal use.

## Hidden invariants (v2)

1. **Aggregate cap unchanged**: outstanding_leased_tokens still
   enforced against `max_total_leased` via the shared `state`.
   Per-worker credits add up to the refill amount; redistribution
   pool absorbs surplus. Total tokens granted per refill window
   ≤ refill_amount.

2. **Work conservation**: when worker A is CPU-bound, its surplus
   flows to redistribution. Worker B that requests more than its
   share gets the surplus. Aggregate throughput is preserved as
   long as ANY worker has unmet demand.

3. **No fairness bypass**: flow-fair queues only call
   `acquire_for_worker_v2`. There is no `my_count == 0 fallback`;
   if a worker has no per-worker credits, it gets 0 from its pool
   and may pull from redistribution (work-conserving). Root traffic
   uses a separate path.

4. **Convergence under flow churn**: epoch CAS serializes
   distribution; each refill window has a single distribution
   pass. Mid-acquire reads of stale counts at most affect one
   refill window's allocation — bounded.

5. **Bounds safety**: `worker_id >= worker_credits.len()` is a bug.
   debug_assert + 0-grant in release. No panic in production.

## Risk assessment (v2)

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | Aggregate cap preserved by shared `state.credits`. Work conservation preserves aggregate when peers are CPU-bound. |
| Lifetime / borrow-checker | LOW | `Box<[AtomicU64]>` and `Box<[AtomicU32]>` owned by lease. Workers access via existing `Arc` deref. |
| Performance regression | MED | Acquire is now 2 CAS loops (own pool + redistribution pool). Worst case: 4-5 atomic ops per acquire. Refill is one CAS for epoch + ~6 atomic adds for distribution. At 5K acquires/sec/worker = ~30K atomic ops/sec total. Profile required to confirm; if measurable, fall back to single-pool acquire and weight only the refill. |
| Architectural mismatch | LOW | This is canonical weighted fair queueing as in HFSC / DRR / WFQ literature. The redistribution pool is the parent-class borrow mechanism. Distinction from #1211 (AFD ECN overlay) is sharp. |
| Saturated workload regression | LOW (NEW) | Work conservation explicitly addresses iperf-c case: CPU-bound workers spill surplus, fast workers absorb. Predicted aggregate at 22.7G saturated: equal to current (no scheduler-side throttle when surplus is available). |

## Test plan (v2)

- Cargo build clean.
- Cargo test --release: 1065+ tests pass.
- New tests in shared_cos_lease unit tests:
  - **Two-worker fair share** (equal demand): each gets ~50% of refill.
  - **Asymmetric flow counts** [4,1]: A gets 80% of refill, B gets 20%.
  - **CPU-bound peer redistribution**: worker B doesn't consume its
    credits; on next refill, B's surplus spills to redistribution;
    worker A pulls from both pools and consumes effectively beyond
    its base share.
  - **Aggregate cap preservation**: 4 workers each requesting more
    than total cap; sum of grants ≤ refill_amount; outstanding_leased
    enforced.
  - **Out-of-range worker_id**: returns 0, no panic.
  - **Sparse worker bindings**: workers 3,4,5 only; workers 0,1,2
    slots stay zero; lease doesn't underrun.
  - **Counter rehydration on flow_fair toggle**: enable/disable cycles
    don't leak counts.
  - **Concurrent acquire** (loom or quickcheck): no underflow on
    state.credits or worker_credits.
- 5x flake check on `shared_cos_lease_v2_two_worker_fair`.
- Go suite: 30 packages pass.
- Cluster smoke matrix: CoS disabled baseline + CoS enabled per-class
  (5201-5206), v4+v6, push+reverse.
- **Targeted iperf-e measurement** (16G EXACT, sub-saturation):
  per-flow CoV target <10% (currently 60%).
- **Targeted iperf-c saturation measurement** (25G shaper, push):
  aggregate target ≥22.0 Gbps (currently 22.7G; allow 3% margin for
  redistribution overhead). observed_cov no worse than 0.21 (recipe
  doc baseline).
- **Targeted CoS-disabled measurement**: per-class CoS off → root
  lease path → must be unchanged from master (Phase 6 only touches
  flow-fair queue lease).

## Out of scope (explicitly)

- Cross-binding redirect (UMEM ownership unchanged).
- Hierarchical CoS parent/child shares.
- Dynamic adjustment of `max_reserve` (the per-worker credit cap).
- HA sync of credit state — strictly per-process, ephemeral.

## Open questions for adversarial review (v2)

1. **Is the math actually fair now?** Per-refill weighted distribution
   into per-worker pools, then drain-own-then-redistribution. Verify
   the limit behavior under sustained acquire skew (Codex's geometric
   series and Gemini's polling-rate examples both apply to v1; do
   they apply to v2?).

2. **Redistribution pool starvation**: can the redistribution pool
   become a hot CAS contention point if many workers are
   simultaneously short on their own credits? At 6 workers × 5K
   acquires/sec = 30K CAS loops/sec on one atomic. Manageable, or
   does this need sharding?

3. **Epoch CAS for refill distribution**: only one worker runs the
   distribution path per epoch. If that worker is the slowest one,
   does the others' refill get delayed? Should ALL workers race the
   distribution but only one wins, with the losers proceeding to
   acquire immediately?

4. **Surplus detection threshold** (`max_reserve = lease_bytes × 2`):
   is this the right boundary? Too low → overactive spilling
   (work loss to redistribution latency). Too high → CPU-bound
   workers hoard credits, redistribution is slow to feed lease-
   starved workers. Empirical tuning likely needed.

5. **Counter rehydration race**: explicit init on
   enable_test_flow_fair / production promotion. Is there a window
   where `acquire_for_worker_v2` is called before the bucket count
   is rehydrated, getting 0 from own pool, dipping into
   redistribution? Bounded by promotion duration (~us) but could
   feel like a brief greedy moment.

6. **Iperf-c saturated regression assumption**: v2 claims work
   conservation preserves aggregate. The recipe doc shows worker
   throttling at 22.7G is sender-side TCP, not scheduler. If
   observed_cov stays at ~21% (sender floor) AND aggregate stays
   at 22.7G, mechanism is sound but value is reduced (only iperf-
   e-class shaper-bound workloads see the win). Acceptable scope?

7. **Root lease still greedy**: control / unclassified traffic
   uses the legacy greedy path. Could a misconfiguration or
   protocol mismatch cause flow-fair traffic to fall onto the
   root path and bypass v2 fairness? cos/admission.rs eligibility
   check needs verification.

8. **Worker ID sourced from `last_planned_workers`**: per
   coordinator/mod.rs:1040, this sizes V_min floors. v2 reuses it
   for credit array sizing. Safe? Or does
   `last_planned_workers` change at runtime (e.g., HA failover),
   leaving credit arrays stale-sized?

9. **Memory cost**: 6 workers × 16 bytes × 7 classes = 672 bytes
   per lease. Plus redistribution pool. Trivial. Confirmed?

10. **HA sync**: v1 review confirmed CoS lease is per-process. v2
    adds new fields but stays per-process. Re-confirm against
    pkg/cluster session/state sync paths.

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
