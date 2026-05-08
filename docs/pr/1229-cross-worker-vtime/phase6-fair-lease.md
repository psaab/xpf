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

**v5 dispatched 2026-05-07 — fixes the three fatal integration holes Codex
identified in v4 ("PLAN-KILL as written, but salvageable").**

## v4 KILL summary (preserved)

Codex ([task-mowiijtx-pn6u07](#)) verdict: "PLAN-KILL as written. The
core direction is no longer obviously wrong: flow-proportional shares
plus a single class reservation atomic is the right spine. But v4
still has fatal integration holes."

Three fatal integration holes (Codex-prioritized):

1. **Epoch rotation is unsafe** — pseudocode CASes `epoch_seq` from
   whatever value just loaded, so peers entering before
   `epoch_start_ns` is published can also "win" rotation. Even with
   a single winner, peers can acquire while `epoch_total_granted`
   has been reset but `epoch_start_ns`, cap, shares, and grace are
   stale. Publishing start last does NOT create a coherent snapshot.
   Required fix: seqlock/odd-even rotating state, or CAS
   `epoch_start_ns` as the rotation claim and make acquirers spin
   while rotation is in progress.

2. **Token lifecycle hand-waved**: acquire CASes
   `epoch_total_granted` (new); legacy `state.credits` is a
   separate packed CAS for `(available, outstanding)`. Two
   independent commit points with no rollback story. If class CAS
   succeeds and credits CAS fails: leak epoch budget. Vice versa:
   leak outstanding/tokens. Required fix: linearized two-CAS-with-
   rollback OR single packed state.

3. **Rehydration "zero race" is false**: coordinator currently
   builds leases from forwarding config, NOT worker-local
   `FlowFairState`. `active_flow_buckets` lives inside worker-owned
   state. A coordinator walk would be impossible, stale, or racy
   without a worker snapshot protocol. Required fix: rehydrate
   worker-side at lease install, under that worker's single-
   threaded ownership.

Other findings (Codex):
- Surplus-sharing exact queues, transparent queues, non-exact
  refill, and root lease all bypass v4. Scope must explicitly say
  "Guarantee-phase exact queue lease only".
- `worker_id > 0` precondition required for surplus path (zero-
  active workers should not drain class budget).
- `max_worker_id` must be TRUE max id, not `workers.len()`.

Gemini ([task-mowiinqd-lze4io](#)) reached a similar fatal-list but
recommended STOP. **Per user calibration ("discount Gemini, wrong a
lot"), Codex's "salvageable, redesign v5" is the operative signal.**

---

## v5 design — three fatal-hole fixes

v5 retains the v4 spine (flow-proportional share, linearizable
class CAS, capped elapsed, grace period) and patches the three
fatal integration holes.

### v5.1 Seqlock-style epoch rotation (Fatal #1 fix)

Use odd-even seqlock pattern. `epoch_seq` increments to ODD when
rotation starts; all updates happen; increments to EVEN when done.
Acquire path snapshots epoch state with seqlock-read pattern.

```rust
// Per-class state (renamed from v4's loose atomics):
struct SharedCoSEpochState {
    // Bit 0 of seq: 0=stable, 1=rotating. Increments by 2 per
    // rotation (so the upper bits double as a generation counter).
    epoch_seq: AtomicU64,
    // The following are "snapshot" fields; readers must verify
    // seq stability across read.
    epoch_start_ns: AtomicU64,
    epoch_total_grant_cap: AtomicU64,
    epoch_grace_expires_ns: AtomicU64,
    // Grant atomic — written by every acquire, reset by rotation.
    // NOT part of the seqlock snapshot; readers may CAS this
    // freely (see v5.2 for cap enforcement).
    epoch_total_granted: AtomicU64,
}

fn maybe_rotate_epoch_v5(lease: &SharedCoSQueueLease, now_ns: u64) {
    // Try to claim rotation by transitioning seq from EVEN→ODD.
    // Loop until either we win or someone else's odd seq is
    // visible (in-progress rotation).
    let seq = lease.epoch.epoch_seq.load(Acquire);
    if seq & 1 == 1 {
        return; // peer rotating; we'll proceed against fresh state
                // after spinning in acquire if needed
    }
    // Check if rotation is even DUE.
    let start = lease.epoch.epoch_start_ns.load(Acquire);
    if now_ns < start.saturating_add(EPOCH_DURATION_NS) {
        return;
    }
    // Atomically transition seq to ODD; only one winner per cycle.
    if lease.epoch.epoch_seq
        .compare_exchange(seq, seq + 1, AcqRel, Acquire).is_err()
    {
        return; // peer claimed
    }
    // We are the rotation winner. seq is now ODD; acquire-path
    // readers will spin or treat us as in-progress until we
    // publish EVEN.

    // Reset class-wide grant atomic FIRST (no readers depend on
    // this for snapshot consistency; cap CAS path is independent).
    lease.epoch.epoch_total_granted.store(0, Release);

    // Reset per-worker grants.
    for grant in lease.worker_grants.iter() {
        grant.store(0, Release);
    }

    // Recompute class-wide flow total + per-worker fair shares.
    let total_flows: u64 = lease.worker_active_flow_buckets
        .iter()
        .map(|c| c.load(Relaxed) as u64)
        .sum::<u64>()
        .max(1);
    let elapsed_ns = (now_ns - start).min(EPOCH_DURATION_NS);
    let new_cap = ((lease.config.rate_bytes as u128)
        * (elapsed_ns as u128) / 1_000_000_000u128) as u64;

    // Publish snapshot fields. ORDER does not matter here because
    // readers verify seq stability after reading; seqlock semantics
    // make these stores together effectively atomic.
    lease.epoch.epoch_total_grant_cap.store(new_cap, Release);
    let grace_ns = now_ns.saturating_add(EPOCH_DURATION_NS / 2);
    lease.epoch.epoch_grace_expires_ns.store(grace_ns, Release);
    for (id, count_atom) in lease.worker_active_flow_buckets.iter().enumerate() {
        let my_count = count_atom.load(Relaxed) as u64;
        let my_share = ((new_cap as u128) * (my_count as u128) / (total_flows as u128)) as u64;
        lease.worker_fair_share[id].store(my_share, Release);
    }
    // epoch_start_ns is part of the snapshot.
    lease.epoch.epoch_start_ns.store(now_ns, Release);

    // FINALLY transition seq to EVEN (publish completion).
    // This release-store synchronizes with acquire-loads of seq
    // in the read snapshot path.
    lease.epoch.epoch_seq.store(seq + 2, Release);
}
```

### v5.2 Seqlock-read snapshot at acquire start

Acquire reads coherent snapshot of (start, cap, grace, my_share)
across the seqlock; class CAS and per-worker CAS use independent
linearization (they don't need the snapshot, just the CURRENT cap
value which the snapshot provides).

```rust
fn acquire_v5(
    lease: &SharedCoSQueueLease,
    worker_id: usize,
    now_ns: u64,
    requested: u64,
) -> u64 {
    if requested == 0 { return 0; }
    if worker_id >= lease.worker_fair_share.len() {
        debug_assert!(false);
        return 0;
    }

    // Phase 1: maybe rotate (claim if eligible).
    maybe_rotate_epoch_v5(lease, now_ns);

    // Phase 2: seqlock snapshot of stable epoch state.
    let (epoch_total_grant_cap, my_fair_share, grace_expires_ns) = loop {
        let seq_before = lease.epoch.epoch_seq.load(Acquire);
        if seq_before & 1 == 1 {
            // Rotation in progress. Spin briefly.
            std::hint::spin_loop();
            continue;
        }
        let cap = lease.epoch.epoch_total_grant_cap.load(Acquire);
        let share = lease.worker_fair_share[worker_id].load(Acquire);
        let grace = lease.epoch.epoch_grace_expires_ns.load(Acquire);
        let seq_after = lease.epoch.epoch_seq.load(Acquire);
        if seq_after == seq_before {
            break (cap, share, grace);
        }
        // Rotation occurred during read; retry.
    };

    let mut total_granted: u64 = 0;
    let mut still_needed = requested;

    // === PRIMARY PATH: bounded by per-worker fair share ===
    loop {
        if still_needed == 0 { break; }
        let my_consumed = lease.worker_grants[worker_id].load(Acquire);
        if my_consumed >= my_fair_share { break; }
        let class_granted = lease.epoch.epoch_total_granted.load(Acquire);
        if class_granted >= epoch_total_grant_cap { break; }

        let class_room = epoch_total_grant_cap - class_granted;
        let my_room = my_fair_share - my_consumed;
        let take = still_needed.min(class_room).min(my_room);
        if take == 0 { break; }

        // Two-CAS with rollback (Codex Fatal #2 fix).
        // Order: epoch_total_granted FIRST (cap enforcement),
        // outstanding SECOND (in-flight cap).
        if lease.epoch.epoch_total_granted
            .compare_exchange_weak(class_granted, class_granted + take,
                AcqRel, Acquire).is_err()
        {
            continue; // contention; retry outer loop
        }
        // Epoch CAS won. Now CAS legacy state.credits to enforce
        // outstanding-leased cap.
        if !try_bump_outstanding(&lease.state, take, lease.config.max_total_leased) {
            // Rollback epoch reservation we just made. fetch_sub
            // is safe because we own the increment.
            lease.epoch.epoch_total_granted.fetch_sub(take, AcqRel);
            break; // outstanding cap reached; can't take more this epoch
        }
        // Both CASes succeeded; commit per-worker counter.
        lease.worker_grants[worker_id].fetch_add(take, AcqRel);
        total_granted += take;
        still_needed -= take;
    }

    // === SURPLUS PATH: only after grace AND only for active workers ===
    let active = lease.worker_active_flow_buckets[worker_id]
        .load(Relaxed) > 0;
    if still_needed > 0 && now_ns >= grace_expires_ns && active {
        loop {
            if still_needed == 0 { break; }
            let class_granted = lease.epoch.epoch_total_granted.load(Acquire);
            if class_granted >= epoch_total_grant_cap { break; }
            let class_room = epoch_total_grant_cap - class_granted;
            let take = still_needed.min(class_room);
            if take == 0 { break; }
            if lease.epoch.epoch_total_granted
                .compare_exchange_weak(class_granted, class_granted + take,
                    AcqRel, Acquire).is_err()
            {
                continue;
            }
            if !try_bump_outstanding(&lease.state, take, lease.config.max_total_leased) {
                lease.epoch.epoch_total_granted.fetch_sub(take, AcqRel);
                break;
            }
            lease.worker_grants[worker_id].fetch_add(take, AcqRel);
            total_granted += take;
            still_needed -= take;
        }
    }

    total_granted
}

#[inline]
fn try_bump_outstanding(
    state: &SharedCoSLeaseState,
    take: u64,
    max_total_leased: u64,
) -> bool {
    loop {
        let credits = state.credits.load(Acquire);
        let (available, outstanding) = unpack_shared_cos_lease_credits(credits);
        if outstanding.saturating_add(take) > max_total_leased {
            return false;
        }
        // Note: `available` is unused in v5 path — rate is enforced
        // by epoch_total_granted, NOT by available. We keep available
        // accounting for legacy callers (root lease etc.) but don't
        // decrement it here. See v5.4.
        let new_credits = pack_shared_cos_lease_credits(
            available,
            outstanding + take,
        );
        if state.credits.compare_exchange_weak(credits, new_credits,
            AcqRel, Acquire).is_ok()
        {
            return true;
        }
    }
}
```

### v5.3 Worker-side rehydration (Fatal #3 fix)

`SharedCoSQueueLease::new` no longer takes
`initial_active_flow_buckets`. Instead, when a worker installs a new
lease (post-Arc-swap), it walks its OWN `FlowFairState` queues bound
to the lease and writes its current count to
`new_lease.worker_active_flow_buckets[my_worker_id]`. This is
single-threaded per worker (worker owns its FlowFairState) — no race.

```rust
// In worker_loop's lease-install path (worker/mod.rs:805 area):
fn rehydrate_lease_for_worker(
    new_lease: &SharedCoSQueueLease,
    my_worker_id: usize,
    my_queues_bound_to_lease: &[&CoSQueueRuntime],
) {
    let total: u32 = my_queues_bound_to_lease.iter()
        .filter_map(|q| q.flow_fair_state.as_ref())
        .map(|ff| ff.active_flow_buckets)
        .sum();
    new_lease.worker_active_flow_buckets[my_worker_id]
        .store(total, Relaxed);
}
```

Until ALL workers have rehydrated, the lease's
`worker_active_flow_buckets` is partially populated. During this
window, total_flows in the new lease is too low; per-worker fair
shares are correspondingly skewed. Bound: rehydration completes
within a few µs of lease swap (per-worker walk is fast and
single-threaded). Transient over-grant is bounded by the rehydration
duration × rate.

### v5.4 Token lifecycle: legacy state.credits is now SEPARATE accounting

The relationship between v5's `epoch_total_granted` and legacy
`state.credits` is now made explicit:

- **`epoch_total_granted`** enforces the per-epoch RATE cap
  (linearizable, all v5 grants CAS against it).
- **`state.credits.outstanding_leased_tokens`** enforces the
  outstanding-leased cap (max in-flight bytes from this lease,
  drained by `consume()` after TX completion).
- **`state.credits.available_tokens`** and the legacy refill path
  are NO-OPS for v5 callers — v5 doesn't read or decrement them.
  Legacy callers (root lease, transparent-rate, surplus-sharing
  exact post-Guarantee phase) continue using them via the legacy
  `shared_cos_lease_acquire` function.

This means v5 and legacy callers MUST NOT share a
`SharedCoSQueueLease` instance. The class-of-service compiler must
allocate v5 leases for Guarantee-phase exact queues only; legacy
leases for everything else. `matches_config` includes the v5/legacy
mode flag.

### v5.5 Explicit scope (Codex point 4 fix)

v5 path applies ONLY to:
- Guarantee-phase exact queue lease acquisition for queues that
  have flow-fair state enabled.

Everything else uses legacy:
- Root lease (`SharedCoSRootLease`) — unchanged, uses
  `state.credits` directly.
- Surplus-sharing exact queues in surplus phase — bypass queue
  lease (per `cos/queue_service/mod.rs:616`). Unchanged.
- Transparent-rate queues — bypass queue lease. Unchanged.
- Non-exact (excess-sharing) queues — use legacy refill path.

The compiler distinguishes v5 vs legacy lease at config-compile
time. `SharedCoSQueueLease::new_v5(...)` creates a v5-mode lease;
`SharedCoSQueueLease::new(...)` (legacy) is unchanged. v5 leases
expose the new `acquire_v5` entry; legacy leases expose the old
`acquire` (unchanged).

### v5.6 max_worker_id sourcing

Coordinator computes `max_worker_id` as TRUE maximum worker_id
seen across the worker map (NOT `workers.len()` which is the
count). Coordinator passes it to `SharedCoSQueueLease::new_v5(...,
max_worker_id)`.

For HA failover or runtime config changes that grow `max_worker_id`,
the lease is rebuilt via existing config-change reconcile;
`matches_config` includes `max_worker_id`. Rebuild happens at the
queue-lease Arc swap point; workers rehydrate their own slots
(§v5.3) and the lease becomes immediately usable.

### v5.7 Surplus precondition (Codex point 7 fix)

The surplus path is gated on `active_flow_buckets[id] > 0`. Workers
with no active flow buckets cannot drain surplus (they have no
flow-fair traffic; if they have OTHER traffic, that uses legacy
path).

## Public API preservation (v5)

- `SharedCoSQueueLease::new` (legacy) — UNCHANGED.
- `SharedCoSQueueLease::new_v5(config, max_worker_id, ...)` — NEW.
- `SharedCoSQueueLease::acquire` (legacy) — UNCHANGED.
- `SharedCoSQueueLease::acquire_v5(worker_id, now_ns, requested)` — NEW.
- `SharedCoSQueueLease::consume(bytes)` — unchanged. Decrements
  `outstanding_leased_tokens`. v5 callers also call this.
- `SharedCoSRootLease::*` — UNCHANGED.
- `matches_config` extended to include v5/legacy mode flag and
  `max_worker_id`.

## Hidden invariants (v5)

1. **Linearizable cap**: `epoch_total_granted ≤ epoch_total_grant_cap`
   always. CAS-enforced.
2. **Outstanding-leased cap**: `outstanding_leased_tokens ≤
   max_total_leased` always. Two-CAS with rollback ensures atomic
   commit.
3. **Seqlock snapshot consistency**: acquire reads (start, cap,
   grace, share) under seqlock-read; verifies seq stability before
   using values. Stale reads are retried.
4. **Worker-side rehydration**: each worker writes its OWN slot at
   lease install. Single-writer-per-slot invariant preserved.
5. **Bounded burst**: `elapsed_ns ≤ EPOCH_DURATION_NS` capped.
6. **Scope**: v5 path enforces v5 invariants; legacy path enforces
   legacy invariants. They do not share state, so neither violates
   the other's invariants.

## Risk assessment (v5)

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | v5 scope strictly Guarantee-phase exact queue lease. Legacy paths unchanged. |
| Lifetime / borrow-checker | LOW | All new state is `Box<[Atomic]>` owned by lease. |
| Performance regression | MED | Acquire is 2 CASes (epoch + outstanding) plus per-worker increment. ~5K acquires/sec/worker = ~10K CAS/sec/worker on shared atomics. Acceptable. Seqlock-read adds 3 atomic loads at acquire start; negligible. |
| Concurrency / correctness | MED-LOW | Seqlock pattern is well-established. Two-CAS-with-rollback is straightforward. Worker-side rehydration is single-writer per slot. The principal residual risk is rare timing edge cases in epoch rotation; covered by tests. |
| Saturated workload regression | LOW | Same as v4. Grace period bounds polling skew; doesn't help CPU-bound workers (acknowledged trade-off). iperf-c expected to maintain ~22.7G aggregate. |

## Test plan (v5)

(All v4 tests retained, plus:)
- **Seqlock rotation snapshot consistency**: concurrent acquire +
  rotation; verify acquirer never observes torn (start, cap, grace,
  share) tuple.
- **Two-CAS rollback**: synthetic stress test that forces
  outstanding-cap to be reached mid-acquire; verify epoch counter is
  rolled back exactly (no over-allocation, no leak).
- **Worker-side rehydration on lease swap**: install new lease while
  6 workers are mid-acquire; verify final
  `worker_active_flow_buckets` matches sum-of-FlowFairState counts.
- **Mode-isolation**: test that v5 lease doesn't grant against
  legacy `state.credits.available_tokens` and vice versa.
- **Inactive worker no-surplus**: worker with `active_flow_buckets[id]
  = 0` post-grace cannot drain surplus.

## Open questions for adversarial review (v5)

1. **Seqlock pattern correctness under preemption**: rotation winner
   advances seq EVEN→ODD, then is preempted for milliseconds. Acquire
   path spins on `seq & 1 == 1` indefinitely. Does the spin have a
   timeout? Should it return 0 after N spins to avoid livelock under
   pathological scheduling?

2. **Two-CAS rollback overshoot under concurrency**: 6 peers all CAS
   epoch_total_granted simultaneously, all succeed (each CASing
   different observed values), then all 6 try outstanding_leased CAS.
   If outstanding cap allows only 2 of 6, the other 4 rollback. Net:
   correct. But the 4 rollbacks each consumed one CAS attempt. Worst-
   case acquire latency? Bounded by max-retries.

3. **Worker-side rehydration correctness**: each worker writes its
   OWN slot. But workers share the lease's
   `worker_active_flow_buckets` Box. If two workers happen to install
   the new lease concurrently (different slots), is the
   single-writer-per-slot guarantee actually held by the lease swap
   protocol? Need to verify against `worker/mod.rs:805` Arc-swap
   semantics.

4. **iperf-c saturated CPU-bound case**: explicitly NOT fixed by
   grace period (acknowledged limitation). Aggregate at 22.7G with
   [6,5,1] distribution: A and B are CPU-bound at ~5.5G each; their
   primary share is 12.5G/10.42G respectively. They can't consume
   that much. Surplus opens at grace; C tries to claim. Net
   aggregate may DROP if C's CPU is also bound. What's the realistic
   prediction? Test must validate or invalidate.

5. **Mode flag in `matches_config`**: v5 vs legacy at compile time.
   What about an exact queue with surplus_sharing enabled? Surplus-
   sharing post-Guarantee uses legacy path; is the SAME lease
   instance OK for both modes? If so, the lease must support
   acquire_v5 AND legacy acquire — which contradicts §v5.4 "v5 and
   legacy callers must NOT share a lease instance". Which is
   correct?

6. **available_tokens semantics for v5 leases**: §v5.4 says v5
   doesn't read/decrement available_tokens. But available_tokens
   refill at rate × elapsed continues. So available_tokens grows
   without bound for v5 leases. Is that just a memory leak (no, it's
   capped at u32::MAX), or does it affect anything?

7. **try_bump_outstanding semantics**: rolls back if outstanding cap
   reached. But if outstanding is high because many in-flight grants
   haven't been consumed, the v5 grant fails. Workers may stall
   waiting for consume(). Is the worst-case latency acceptable?
   Bounded by TX completion time.

8. **Grace period and CPU-bound workers**: explicitly disclosed as
   not fixed by v5. Acceptable scope?

9. **Sender-side TCP floor**: same as before. iperf-c saturated
   observed_cov stays ~21% from sender side. v5's value is on
   shaper-bound workloads (iperf-e style).

10. **Round-5 architectural completeness**: any token paths v5
    misses? Surplus-sharing post-Guarantee, transparent-rate, root
    lease, non-exact — all explicitly scoped to legacy. Anything
    else?

## v3 KILL summary (preserved)

Third consecutive convergent kill. Codex
([task-mowi4us3-q561pl](#)) + Gemini Pro 3
([task-mowi4yo4-s0bwf5](#)).

Convergent fatal findings:

1. **Primary/surplus race breaks aggregate cap**: fast worker A
   takes primary + surplus before slow B polls; B later still
   takes primary share → total exceeds cap.
2. **Concurrent surplus N×batch overshoot**: all N peers see
   same `surplus_avail`, each CAS independent counter, all
   succeed → overshoot is `N × batch_size`, not `1 × batch_size`.
3. **Worker-count denominator abandons flow-fairness**: `n_active`
   instead of `total_active_flows` gives [4 flows, 1 flow]
   workers each 50% of cap. Single-flow worker gets 4× per-flow
   rate. Plan even contradicts itself (iperf-c story uses 1/12
   per-flow, algorithm uses 1/n_workers).
4. **Unbounded burst on jitter**: `new_cap = rate × elapsed_ns`
   with no upper bound → 10ms idle = 20 MB burst.
5. **Counter rehydration window unbounded**: existing
   `account_cos_queue_flow_enqueue` only counts 0→nonzero
   transitions; already-queued buckets don't repopulate new
   lease post-Arc-swap.
6. **"No tokens" claim is false**: bytes flow into
   `queue.hot.tokens` and live across epoch resets. Making
   `consume` a no-op loses outstanding-token accounting without
   redesigning selection to grant only for immediate TX.

Codex constructive v4 prescription: "primary grant only for
active/requesting workers, explicit rehydration on lease
install, linearizable class-total reservation, safe epoch
rotation, either no immediate borrowing of peer primary share
or bounded debt/repayment for borrowed surplus."

Gemini constructive v4 prescription: "1) restore proportional
share (my_active_flows × total_cap / total_active_flows);
2) global granted counter — ALL acquires CAS against
epoch_total_granted; 3) cap elapsed_ns ≤ EPOCH_DURATION_NS."

---

## v4 design — flow-proportional + linearizable cap + bounded surplus

v4 incorporates **every convergent v3 fix** from both reviewers.

### v4.1 Per-worker flow-count weighted share (Gemini #3 fix)

```rust
// FLOW-proportional fair share, NOT worker-proportional.
my_fair_share = (worker_active_flow_buckets[id] as u64 × total_cap)
                / total_active_flow_buckets
```

Where `total_active_flow_buckets = sum_over_workers(active_flow_buckets)`.

Computed at epoch rotation, snapshotted into per-worker
`worker_fair_share[id]` array (length max_worker_id+1) for fast
acquire-time read. This restores #1229's flow-fairness invariant
that v3 broke.

### v4.2 Single class-wide `epoch_total_granted` atomic (Gemini #2 fix)

```rust
struct SharedCoSEpochState {
    epoch_start_ns: AtomicU64,
    epoch_total_grant_cap: AtomicU64,
    epoch_total_granted: AtomicU64,        // <-- NEW v4
    epoch_grace_expires_ns: AtomicU64,     // <-- NEW v4
    epoch_seq: AtomicU64,
}
```

ALL grants (primary AND surplus) CAS against `epoch_total_granted`.
The class-wide cap is linearizable: total grants this epoch ≤
`epoch_total_grant_cap`, always.

### v4.3 Capped elapsed_ns (Gemini #4 fix)

```rust
let elapsed_ns = (now_ns - start).min(EPOCH_DURATION_NS);
let new_cap = ((rate_bytes as u128) * (elapsed_ns as u128)
               / 1_000_000_000u128) as u64;
```

Even if the rotation winner is preempted for 10ms, `new_cap`
caps at one epoch's worth. Burst bounded to ≤ MTU × small N
(consistent with Junos shaper expectations).

### v4.4 Acquire path with linearizable cap

```rust
fn acquire_v4(
    lease: &SharedCoSQueueLease,
    worker_id: usize,
    now_ns: u64,
    requested: u64,
) -> u64 {
    if requested == 0 { return 0; }
    if worker_id >= lease.worker_fair_share.len() {
        debug_assert!(false);
        return 0;
    }

    maybe_rotate_epoch_v4(lease, now_ns);

    let total_cap = lease.epoch.epoch_total_grant_cap.load(Acquire);
    let my_fair_share = lease.worker_fair_share[worker_id].load(Acquire);
    let grace_expires = lease.epoch.epoch_grace_expires_ns.load(Acquire);

    let mut total_granted: u64 = 0;
    let mut still_needed = requested;

    // === PRIMARY PATH: capped at my_fair_share AND class total ===
    loop {
        if still_needed == 0 { break; }
        let class_granted = lease.epoch.epoch_total_granted.load(Acquire);
        if class_granted >= total_cap { break; } // class cap reached
        let my_consumed = lease.worker_grants[worker_id].load(Acquire);
        if my_consumed >= my_fair_share { break; } // my primary done

        let class_room = total_cap - class_granted;
        let my_room = my_fair_share - my_consumed;
        let take = still_needed.min(class_room).min(my_room);
        if take == 0 { break; }

        // Linearizable: bump class total FIRST. If that succeeds,
        // bump per-worker counter (advisory, used to bound primary
        // path).
        if lease.epoch.epoch_total_granted
            .compare_exchange_weak(
                class_granted, class_granted + take,
                AcqRel, Acquire)
            .is_ok()
        {
            lease.worker_grants[worker_id].fetch_add(take, AcqRel);
            total_granted += take;
            still_needed -= take;
        }
        // Retry loop on contention.
    }

    // === SURPLUS PATH: only AFTER grace period expires ===
    // This bounds polling skew: fast workers can't snap up slow
    // workers' reserved share within the first half of an epoch.
    if still_needed > 0 && now_ns >= grace_expires {
        loop {
            if still_needed == 0 { break; }
            let class_granted = lease.epoch.epoch_total_granted.load(Acquire);
            if class_granted >= total_cap { break; }
            let class_room = total_cap - class_granted;
            let take = still_needed.min(class_room);
            if take == 0 { break; }
            if lease.epoch.epoch_total_granted
                .compare_exchange_weak(
                    class_granted, class_granted + take,
                    AcqRel, Acquire)
                .is_ok()
            {
                lease.worker_grants[worker_id].fetch_add(take, AcqRel);
                total_granted += take;
                still_needed -= take;
            }
        }
    }

    total_granted
}
```

### v4.5 Epoch rotation with grace-period publish

```rust
fn maybe_rotate_epoch_v4(lease: &SharedCoSQueueLease, now_ns: u64) {
    let start = lease.epoch.epoch_start_ns.load(Acquire);
    if now_ns < start.saturating_add(EPOCH_DURATION_NS) { return; }

    let seq = lease.epoch.epoch_seq.load(Acquire);
    if lease.epoch.epoch_seq
        .compare_exchange(seq, seq + 1, AcqRel, Acquire).is_err()
    {
        return;
    }

    // Reset per-worker grants.
    for grant in lease.worker_grants.iter() { grant.store(0, Release); }

    // Reset class total grants.
    lease.epoch.epoch_total_granted.store(0, Release);

    // Recompute class-wide total active flow buckets.
    let total_flows: u64 = lease.worker_active_flow_buckets
        .iter()
        .map(|c| c.load(Relaxed) as u64)
        .sum::<u64>()
        .max(1); // avoid div-by-zero

    // Compute new epoch cap (capped elapsed for jitter).
    let elapsed_ns = (now_ns - start).min(EPOCH_DURATION_NS);
    let new_cap = ((lease.config.rate_bytes as u128)
        * (elapsed_ns as u128)
        / 1_000_000_000u128) as u64;
    lease.epoch.epoch_total_grant_cap.store(new_cap, Release);

    // Recompute per-worker fair shares (FLOW-proportional).
    for (id, count_atom) in lease.worker_active_flow_buckets.iter().enumerate() {
        let my_count = count_atom.load(Relaxed) as u64;
        let my_share = if total_flows > 0 {
            ((new_cap as u128) * (my_count as u128) / (total_flows as u128)) as u64
        } else { 0 };
        lease.worker_fair_share[id].store(my_share, Release);
    }

    // Publish grace period: surplus available after half of epoch.
    let grace_ns = now_ns.saturating_add(EPOCH_DURATION_NS / 2);
    lease.epoch.epoch_grace_expires_ns.store(grace_ns, Release);

    // Publish epoch_start_ns LAST so peers entering acquire see
    // fresh state once they observe the new start.
    lease.epoch.epoch_start_ns.store(now_ns, Release);
}
```

### v4.6 Explicit rehydration on lease install (Codex F5 fix)

When a `SharedCoSQueueLease` is constructed (or replaced via
config-change reconcile), the coordinator walks all queues bound
to the lease and snapshots their current `active_flow_buckets`
into the lease's `worker_active_flow_buckets[id]` counters.

```rust
impl SharedCoSQueueLease {
    pub fn new(
        config: SharedCoSLeaseConfig,
        max_worker_id: usize,
        initial_active_flow_buckets: &[(usize /*worker_id*/, u32)],
    ) -> Arc<Self> {
        let mut lease = SharedCoSQueueLease { /* ... */ };
        for (id, count) in initial_active_flow_buckets {
            lease.worker_active_flow_buckets[*id].store(*count, Relaxed);
        }
        Arc::new(lease)
    }
}
```

The coordinator's lease-install path enumerates queues bound to
the lease (already needed for `matches_config`) and computes the
initial counts. This eliminates the rehydration race window
entirely; v3's "bounded to one epoch" claim is replaced with
"zero".

### v4.7 Token lifecycle integration (Codex F4 fix)

`shared_cos_lease_acquire_v4` grants bytes into the existing
`queue.hot.tokens` flow EXACTLY as the legacy path does. The
v4 grant IS the lease's contribution to local tokens. The
existing `release_unused` path (`token_bucket.rs:224`) continues
to release back to the lease's outstanding-tokens accounting.

Specifically, v4 retains:
- `state.credits` aggregate accounting (refilled at epoch
  rotation, decremented on grant) — but with the v4
  semantics that "available" is bounded by
  `epoch_total_grant_cap - epoch_total_granted`, NOT by
  `state.credits` alone.
- `outstanding_leased_tokens` for cap on uncommitted lease.
- `bump_outstanding_leased(state, take)` after each successful
  grant.

The `consume` path is UNCHANGED. v4 doesn't claim "no tokens";
it claims "no per-worker token POOLS that accumulate across
epochs". Per-worker grants reset every epoch; class-wide
outstanding tokens continue to use existing accounting.

### v4.8 Surplus grace period (Codex "bounded debt" alternative)

The grace period is a simpler alternative to bounded debt:
within the first half of an epoch (100µs of 200µs), no worker
can claim surplus. This guarantees that ANY worker polling
within the first 100µs gets its primary fair share. After
100µs, surplus path opens — at this point, a slow worker that
hasn't polled forfeits its share for this epoch.

Grace period assumes worker polling cadence < 100µs in
saturation. From `cos/queue_service/mod.rs:419` and
`token_bucket.rs:64`, lease top-up is called whenever
queue.hot.tokens drops below the lease target — this happens
every TX batch (~µs cadence under saturation), well within
100µs.

Trade-off vs bounded debt: grace period bounds polling skew per
epoch but loses some work conservation if a worker is genuinely
absent. Bounded debt would carry the slow worker's unconsumed
share to the next epoch as a credit, restoring full work
conservation but requiring per-epoch debt settlement logic.
v4 picks the simpler option; v5 could revisit if iperf-c
saturation regression is observed.

## Public API preservation (v4)

- `SharedCoSQueueLease::new` signature CHANGES: gains
  `max_worker_id: usize` AND `initial_active_flow_buckets:
  &[(usize, u32)]` parameters.
- `SharedCoSQueueLease::acquire` signature CHANGES: gains
  `worker_id: usize`. Caller passes `runtime.worker_id`.
- `SharedCoSQueueLease::consume`: UNCHANGED.
- `SharedCoSRootLease::acquire`: UNCHANGED (separate path).
- `matches_config` extended to include `max_worker_id` and
  the canonical worker→queue binding map.
- v4 introduces NO new public types; private internals only.

## Hidden invariants (v4)

1. **Aggregate cap (linearizable)**: `epoch_total_granted ≤
   epoch_total_grant_cap`, always. CAS-enforced on every grant.
   No primary/surplus race possible.
2. **Per-epoch flow-proportional share**: each worker's primary
   path bounded by `my_fair_share = my_flows × cap / total_flows`.
3. **Polling-skew bound**: within grace period (100µs of 200µs),
   surplus path is closed. Fast worker cannot drain class budget
   beyond its primary share before slow worker has a chance to
   poll. After grace, surplus opens but is still
   `epoch_total_granted` capped.
4. **Burst bound**: `elapsed_ns ≤ EPOCH_DURATION_NS` capped at
   epoch rotation. Idle gaps don't accumulate.
5. **No fairness bypass**: workers with zero active flow buckets
   have `my_fair_share = 0` (proportional formula). They can
   only enter surplus path after grace, and surplus is class-
   capped.
6. **Bounds safety**: `worker_id >= len()` returns 0, no panic.
   `matches_config` triggers lease rebuild on `max_worker_id`
   change.
7. **Rehydration**: zero race window — initial counts are
   snapshotted into the lease at construction.
8. **Token lifecycle**: existing `state.credits`,
   `outstanding_leased_tokens`, `consume` all preserved. v4
   adds the epoch-grant atomic and per-worker counters as
   ADDITIONAL state, doesn't replace existing accounting.

## Risk assessment (v4)

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | Aggregate cap linearizable; no token leak; existing accounting preserved. |
| Lifetime / borrow-checker | LOW | All new state is `Box<[Atomic]>` owned by lease, accessed via Arc. |
| Performance regression | MED | Acquire is 1-2 CAS loops on `epoch_total_granted` plus per-worker counter increment. At 5K acquires/sec/worker, 30K class-wide CAS/sec on a single atomic. Cache-line contention on the class atomic. Profile required. Mitigation: shard class atomic by 4 (mod worker_id) if measurable. |
| Architectural mismatch | LOW | Standard time-window weighted fair sharing pattern. Distinct from #1211 AFD overlay. |
| Saturated workload regression | LOW | Work conservation via post-grace surplus. CPU-bound peer's unconsumed share is claimable by faster peer in second half of each epoch. |

## Test plan (v4)

(Same as v3, plus:)
- **Linearizable cap test**: 6 concurrent workers each requesting
  `2 × total_cap`, verify sum of grants ≤ total_cap (no overshoot).
- **Polling skew across epochs**: A polls every 10µs, B polls
  every 1ms. After 100 epochs (= 20ms), A:B grant ratio matches
  flow ratio, NOT polling ratio. Critical anti-regression.
- **Flow-proportional fairness**: workers with [4,3,4,1] flows.
  Each per-flow rate within ±5%.
- **Grace-period surplus enforcement**: A polls in first 50µs,
  attempts to claim more than primary share. Verify: returns
  exactly primary share (no surplus). At 150µs (post-grace), A's
  surplus call succeeds up to class room.
- **Jitter burst test**: idle for 5ms, then resume. Verify first
  acquire after resume bounded to one epoch's worth (no 5ms-
  worth burst).
- **Rehydration on lease swap**: install new lease with non-zero
  initial counts. First epoch's `total_flows` reflects existing
  queue state. Aggregate within 5% of steady-state from epoch 1.

## Out of scope (explicitly)

- Bounded debt across epochs (v5 candidate if grace period
  insufficient for genuinely-absent workers).
- Hierarchical CoS parent/child shares.
- HA sync of v4 state (per-process, ephemeral).

## Open questions for adversarial review (v4)

1. **Is the linearizable cap actually preserved?** The CAS on
   `epoch_total_granted` is the cap enforcer. Verify: under
   N concurrent peers, no two CAS operations can both
   succeed at the same value. (CAS semantics handle this.)
   But the per-worker `worker_grants[id].fetch_add` is
   non-atomic with the class CAS — does the order matter for
   any invariant?

2. **Grace period fairness**: 100µs of 200µs is 50% of epoch
   reserved for primary-only. Across many epochs, slow worker
   gets 50% of its primary share during grace + 50% of its
   surplus opportunity post-grace. Total expected = primary
   share. But fast worker also gets 50% of its primary +
   N/(N-1) of surplus opportunity post-grace. Is this fair
   across slow vs fast? Walk through the math.

3. **Class atomic cache contention**: `epoch_total_granted`
   is hit by every grant CAS from every worker. 6 workers ×
   5K acquires/sec = 30K CAS/sec on one cache line. Sharding
   by 4 reduces to 7.5K/shard but introduces read-side cost
   (sum 4 atomics for `class_room` check). Empirical question;
   reasonable default?

4. **Epoch rotation safety**: rotation winner advances seq,
   resets all grants, recomputes shares, publishes start_ns
   LAST. Under contention, peers see seq mismatch and skip
   rotation. Could a peer enter acquire BEFORE the rotation
   winner publishes start_ns, see stale `epoch_total_granted`
   = old value, and grant against the old cap? Bounded by
   the rotation duration (~µs), but is the worst case
   acceptable?

5. **Rehydration via initial_active_flow_buckets**: the
   coordinator walks queues to compute initial counts.
   Walking happens at lease-install time, but flow buckets
   may transition during the walk. Is the resulting count
   consistent? Bounded transient acceptable, or does this
   need locking?

6. **iperf-c saturation work conservation**: at 22.7G with
   [6,5,1] flows and 3 workers, A=6/12=12.5G primary cap,
   B=5/12=10.42G primary, C=1/12=2.08G primary. C consumes
   ~4G (CPU-bound producer). Surplus from A/B post-grace:
   total_cap - sum_grants. If A/B served exactly their
   primary, surplus = 0; nobody steals. If A served only
   8G, surplus = 12.5-8 = 4.5G; available to C
   post-grace. Aggregate: 8 + 10.42 + min(4, 2.08+4.5) =
   ~22.5G. Within 1% of 22.7G. Verify the math.

7. **`my_fair_share = 0` for inactive workers**: surplus
   path is gated only by `now_ns >= grace_expires`, not by
   `my_fair_share > 0`. Could a non-flow-fair worker (e.g.
   one only handling control traffic) drain surplus
   post-grace? Yes — but bounded by `class_room`, so the
   class cap holds. Acceptable, or should we add an
   `active_flow_buckets[id] > 0` precondition for surplus?

8. **Token-lifecycle integration**: v4 keeps `state.credits`
   and `outstanding_leased_tokens` from the legacy state.
   How exactly do v4's per-worker grants interact with
   `state.credits`? Is the v4 grant CAS additive to or
   replacement for the legacy `state.credits` decrement?

9. **`matches_config` extension**: adding `max_worker_id`
   and worker→queue binding map to `matches_config`. What
   triggers a config-change reconcile that would call
   `matches_config`? HA failover, config commit, runtime
   reconfigure. Is the rebuild traffic-safe?

10. **Window duration sensitivity (revisited)**: 200µs
    epoch with 100µs grace. Slow worker polling cadence
    must be < 100µs to get full primary share. From the
    code, lease top-up cadence is per-batch (~µs at
    saturation). Margin is OK. But under low load
    (transient idle, then burst), slow worker may not
    have polled in 100µs → skips primary that epoch. One-
    epoch transient; bounded.

## v3 design: per-epoch fair share (time-window sharing)

User chose option C from the v2 stop-and-report. v3 abandons token
accumulation entirely and uses epoch-bounded per-worker grant
counters that reset every epoch. This addresses every convergent
kill point from v1+v2 because there is no pool to leak, no balance
to steal share from, and no accumulating credit to violate the cap.

### v3.1 Core insight

Rate is `class_rate_bytes_per_sec`. Pick an epoch duration (e.g.
200µs to match current refill cadence). Per-epoch grant cap:

```
epoch_total_grant_cap = class_rate_bytes_per_sec × epoch_duration_sec
                      = 16e9/8 × 200e-6 = 400 KB per epoch (16G class)
```

Each worker's fair share within an epoch:

```
my_fair_share = epoch_total_grant_cap / epoch_active_workers
              = 400 KB / 4 = 100 KB per worker per epoch (4 active workers)
```

Within an epoch, a worker can grant from its **primary share** (up
to `my_fair_share`); once exhausted, it can claim **surplus**
(epoch grant cap minus sum of all per-worker grants). At epoch
boundary, all grant counters reset. Slow workers don't carry their
unused share forward; fast workers don't carry surplus.

### v3.2 State layout

```rust
pub(in crate::afxdp) struct SharedCoSQueueLease {
    // existing config + state retained for legacy callers
    config: SharedCoSLeaseConfig,
    state: SharedCoSLeaseState,

    // NEW v3: epoch state
    epoch: SharedCoSEpochState,

    // NEW v3: dense per-worker active-flow-bucket counters
    // (used for fair-share computation at epoch start). Sized
    // by max_worker_id+1 (sourced from coordinator's
    // dense-worker-id map; see §v3.6).
    worker_active_flow_buckets: Box<[AtomicU32]>,

    // NEW v3: per-worker grants this epoch. Reset to 0 by
    // whichever worker rotates the epoch.
    worker_epoch_grants: Box<[AtomicU64]>,
}

#[repr(align(64))]
struct SharedCoSEpochState {
    // Monotonic ns when current epoch started. Workers compare
    // now_ns against this to decide when to rotate.
    epoch_start_ns: AtomicU64,
    // Total bytes that may be granted in this epoch
    // (= rate × epoch_duration). Set at epoch rotation.
    epoch_total_grant_cap: AtomicU64,
    // Active worker count snapshotted at epoch rotation
    // (workers with active_flow_buckets > 0). Used for
    // primary-share denominator.
    epoch_active_worker_count: AtomicU32,
    // Sequence number for epoch rotation; CAS-serialized so
    // exactly one worker runs the rotation per boundary.
    epoch_seq: AtomicU64,
}

const EPOCH_DURATION_NS: u64 = 200_000; // 200µs
```

### v3.3 Acquire path

```rust
fn shared_cos_lease_acquire_for_worker_v3(
    lease: &SharedCoSQueueLease,
    worker_id: usize,
    now_ns: u64,
    requested: u64,
) -> u64 {
    if requested == 0 {
        return 0;
    }

    // Bounds: out-of-range worker_id returns 0 (not panic).
    // matches_config check on lease replacement ensures this only
    // fires on programming bug.
    if worker_id >= lease.worker_epoch_grants.len() {
        debug_assert!(false, "worker_id out of range");
        return 0;
    }

    // 1) Maybe-rotate epoch.
    maybe_rotate_epoch_v3(lease, now_ns);

    let total_cap = lease.epoch.epoch_total_grant_cap.load(Acquire);
    let n_active = lease.epoch.epoch_active_worker_count.load(Acquire).max(1) as u64;
    let my_fair_share = total_cap / n_active; // floor; remainder
                                               // accessible via surplus

    // 2) Try primary share first.
    let my_grant = &lease.worker_epoch_grants[worker_id];
    let mut total_granted: u64 = 0;
    let mut still_needed = requested;
    loop {
        let curr = my_grant.load(Acquire);
        if curr >= my_fair_share || still_needed == 0 {
            break;
        }
        let take = still_needed.min(my_fair_share - curr);
        if my_grant.compare_exchange_weak(
            curr, curr + take, AcqRel, Acquire).is_ok()
        {
            total_granted += take;
            still_needed -= take;
        }
    }

    // 3) If still needed, claim surplus (sum of all worker grants
    //    must remain ≤ total_cap). Surplus is the running sum of
    //    every other worker's UNCLAIMED primary share + the
    //    floor-division remainder.
    while still_needed > 0 {
        let total_granted_class: u64 = lease.worker_epoch_grants
            .iter()
            .map(|g| g.load(Acquire))
            .sum();
        if total_granted_class >= total_cap {
            break;  // class-wide grant cap reached this epoch
        }
        let surplus_avail = total_cap - total_granted_class;
        let take = still_needed.min(surplus_avail);
        // Atomically bump THIS worker's grant counter. The
        // class-wide sum check above is a snapshot; if a peer
        // bumped concurrently, our take could overshoot by ≤
        // requested per acquire. Bound: per-acquire request
        // size (≤ TX_BATCH_SIZE × MTU). At 32 × 1500 = 48 KB,
        // overshoot bounded to one batch — acceptable transient.
        let curr = my_grant.load(Acquire);
        if my_grant.compare_exchange_weak(
            curr, curr + take, AcqRel, Acquire).is_ok()
        {
            total_granted += take;
            still_needed -= take;
        }
        // CAS retry on contention with peer increments;
        // re-snapshot total_granted_class on next iteration.
    }

    total_granted
}
```

### v3.4 Epoch rotation

```rust
fn maybe_rotate_epoch_v3(
    lease: &SharedCoSQueueLease,
    now_ns: u64,
) {
    let start = lease.epoch.epoch_start_ns.load(Acquire);
    if now_ns < start.saturating_add(EPOCH_DURATION_NS) {
        return; // current epoch still valid
    }

    // CAS the seq to claim rotation. Only one winner runs reset.
    let seq = lease.epoch.epoch_seq.load(Acquire);
    let new_seq = seq + 1;
    if lease.epoch.epoch_seq.compare_exchange(
        seq, new_seq, AcqRel, Acquire).is_err()
    {
        return; // peer rotated; we proceed against fresh state
    }

    // We won the rotation. Reset all per-worker grants to 0.
    for grant in lease.worker_epoch_grants.iter() {
        grant.store(0, Release);
    }

    // Recompute active worker count from per-worker active-flow-
    // bucket counters. This gives the next epoch's denominator.
    let active_count = lease.worker_active_flow_buckets
        .iter()
        .filter(|c| c.load(Relaxed) > 0)
        .count() as u32;
    lease.epoch.epoch_active_worker_count.store(active_count, Release);

    // Compute new epoch total cap.
    let elapsed_ns = now_ns - start; // typically ≈ EPOCH_DURATION_NS
                                      // but may be longer on jitter
    let new_cap = ((lease.config.rate_bytes as u128)
        * (elapsed_ns as u128)
        / 1_000_000_000u128) as u64;
    lease.epoch.epoch_total_grant_cap.store(new_cap, Release);

    // Advance epoch_start_ns LAST so peers entering acquire see
    // the new state once they observe new start.
    lease.epoch.epoch_start_ns.store(now_ns, Release);
}
```

### v3.5 No tokens, no cap-after-grant violation

The acquire path enforces:
- Primary grant ≤ `my_fair_share`.
- Total class-wide grants ≤ `total_cap` (sum check before each
  surplus take).
- Per-acquire surplus overshoot bounded by batch size (≤ 48 KB).

There is NO `state.credits` accumulator that can be violated.
There is NO `outstanding_leased_tokens` that can drift. There is
NO redistribution pool that can leak.

### v3.6 Dense worker-id mapping (Codex F4 / Gemini #5 fix)

The plan requires `worker_epoch_grants.len() ==
worker_active_flow_buckets.len() == max_worker_id + 1`. Construction:

- Coordinator computes `max_worker_id` from the worker map at
  config compile time.
- `SharedCoSQueueLease::new(config, max_worker_id)` sizes both
  arrays to `max_worker_id + 1`.
- `matches_config` is extended to include `max_worker_id`; if
  the dense space changes (HA failover, worker addition), the
  lease is rebuilt during normal config-change reconcile.
- Sparse IDs: gaps stay at 0 forever (workers not bound to this
  lease never request).

This explicitly does NOT use `last_planned_workers`. That value
mutates at runtime (Codex F4) and is `workers.len()` not
`max(worker_id)+1` (Gemini #5).

### v3.7 No `my_count == 0` fallback (Codex F6 / Gemini #10 Bypass 2 fix)

Acquire never falls through to a greedy path. If a worker has
no active flow buckets:
- Its `epoch_active_worker_count` contribution is 0 (filtered out
  in §v3.4).
- Its `my_fair_share` is `total_cap / n_active` where `n_active`
  excludes it; it can still claim surplus via §v3.3 step 3 to
  participate in work-conservation.
- This is intentional and bounded: surplus claiming is capped by
  `total_cap - total_granted_class`, so non-flow-fair workers
  can only consume what flow-fair workers haven't.

Root lease, surplus-sharing exact queues, and transparent-rate
queues use a SEPARATE code path (`shared_cos_lease_acquire_legacy`,
the existing pre-v3 function, retained verbatim). v3 scope is
"Guarantee-phase exact queue lease only" — explicit narrowing per
Codex F6.

### v3.8 Counter rehydration (Codex F5 / Gemini #6 fix)

`worker_active_flow_buckets` is read AT EPOCH ROTATION (§v3.4),
not on every acquire. This eliminates the rehydration race window
to one epoch (200µs). On lease replacement (queue-lease-Arc swap
at `worker/mod.rs:805`), the new lease inherits zeroed counters;
they re-fill via the existing `account_cos_queue_flow_enqueue`
path within the first epoch.

If the lease replacement fires DURING an epoch, the stale-count
window is bounded by `EPOCH_DURATION_NS = 200µs`. Within that
window, surplus claiming preserves work conservation; nobody
starves.

## Public API preservation (v3)

- `SharedCoSQueueLease::new` signature CHANGES: gains
  `max_worker_id: usize` parameter (from coordinator).
- `SharedCoSQueueLease::acquire` signature CHANGES: gains
  `worker_id: usize` parameter. Caller in `cos/token_bucket.rs:64`
  passes `runtime.worker_id`.
- `SharedCoSQueueLease::consume` (release-side): unchanged.
  v3 doesn't track outstanding leased tokens, so consume is a
  no-op for v3 callers. Existing legacy callers continue to use
  the old consume.
- `SharedCoSRootLease::acquire`: unchanged (separate path).
- `matches_config` extended to include `max_worker_id`.

## Hidden invariants (v3)

1. **Aggregate cap**: enforced at every grant. Sum of all
   per-worker grants this epoch ≤ `total_cap` (≤ rate ×
   elapsed_ns). Per-acquire surplus overshoot ≤ batch size,
   bounded.
2. **No long-term token state**: epoch_grants reset every 200µs.
   No accumulating pools. No leaks.
3. **Polling skew protection**: fast poller hits its
   `my_fair_share` cap within an epoch, can only claim surplus.
   Slow poller's primary share is preserved until epoch close;
   surplus available only for the slow poller's UNCLAIMED slice
   (= `my_fair_share - my_grant.load`), bounded.
4. **Work conservation**: within an epoch, fast worker can claim
   slow worker's unclaimed primary share via surplus. Aggregate
   throughput at saturation: sum of (each worker's actual TX) ≤
   `total_cap`, but fast workers get the unused share of slow
   workers. iperf-c case: workers A/B slightly throttled to
   fair share; worker C (1 flow, ~4 Gbps) takes its 1/12 = 0.33
   primary + claims surplus from A/B's unconsumed quota up to
   the 4 Gbps it actually produces. Aggregate preserved.
5. **No fairness bypass**: my_count==0 doesn't fall through to
   greedy; it falls through to surplus, which is capped by
   class total.
6. **Bounds safety**: `worker_id >= len()` returns 0, not panic.

## Risk assessment (v3)

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | No long-term state; epoch reset every 200µs preserves Junos shaper expectations. |
| Lifetime / borrow-checker | LOW | `Box<[AtomicU64]>` and `Box<[AtomicU32]>` owned by lease. Workers access via `Arc` deref. |
| Performance regression | MED | Primary acquire: 1 CAS loop on `worker_epoch_grants[id]`. Surplus acquire: O(N) sum + 1 CAS. At 5K acquires/sec/worker, primary path is 5K CAS/sec/worker; surplus path triggers only when primary share exhausted (saturation). Profile required; if surplus path becomes hot, alternative is a class-wide running counter incremented atomically per grant. |
| Architectural mismatch | LOW | Time-window sharing is canonical (e.g. AVB Credit-Based Shaper, ATM TM 4.1 GCRA, Linux htb borrow). Distinct from #1211 AFD overlay. |
| Saturated workload regression | LOW | Work conservation explicit via surplus; CPU-bound peer's unconsumed share goes to faster peer within the same epoch. iperf-c 22.7G expected to hold. |

## Test plan (v3)

- Cargo build clean.
- Cargo test --release: 1065+ tests pass.
- New tests in shared_cos_lease v3:
  - **Two-worker primary share equal demand**: each gets 50%.
  - **Asymmetric flow counts [4,1]**: A primary 4/5 × cap, B 1/5
    × cap when both fully demand.
  - **Polling skew test**: A polls 10× B; each gets primary 50%
    of cap with occasional surplus from B's unclaimed slice.
    Total NEVER exceeds class cap. Critical anti-regression.
  - **CPU-bound peer surplus claim**: B serves below primary
    share; A claims B's unclaimed share via surplus. Aggregate
    preserved.
  - **Aggregate cap preserved under contention**: 6 workers each
    requesting more than total cap; sum of grants ≤ total_cap.
  - **Epoch rotation correctness**: at boundary, grants reset;
    fair share recomputed; previous epoch's unconsumed share
    does NOT carry forward.
  - **Sparse worker_id**: bound check, no panic.
  - **Out-of-range `worker_id`**: returns 0, no panic.
  - **Counter rehydration on lease swap**: after Arc replacement,
    first epoch may have stale counts; surplus-claim preserves
    work conservation; aggregate within 5% of steady-state.
  - **Concurrent acquire** (loom or quickcheck): no overshoot
    > batch size, no underflow, no negative grants.
- 5x flake check on `shared_cos_lease_v3_polling_skew_protection`.
- Go suite: 30 packages pass.
- Cluster smoke matrix (CoS off + CoS on, v4+v6, push+reverse,
  per-class 5201-5206).
- **Targeted iperf-e measurement** (16G EXACT, sub-saturation):
  per-flow CoV target <10% (currently 60%).
- **Targeted iperf-c saturation measurement** (25G shaper, push):
  aggregate ≥22.0 Gbps; observed_cov no worse than 0.21.
- **Targeted CoS-disabled measurement**: root lease path → master
  baseline (Phase 6 only touches Guarantee-phase exact queue lease).

## Open questions for adversarial review (v3)

1. **Polling skew, again**: critique fires only if a fast poller
   can drain MORE than `my_fair_share` in primary. v3 explicitly
   blocks this via `curr >= my_fair_share` check. Verify the
   surplus path can't be abused: a fast poller could keep
   spinning the surplus loop and snapping every byte that any
   slow peer hasn't claimed yet. Bound: `total_granted_class ≤
   total_cap`, so per-epoch upper bound is `total_cap` — but a
   fast poller could approach 100% of surplus = 100% of
   `total_cap - my_fair_share × N`. Is that an issue?

2. **Per-acquire O(N) sum of grants**: surplus-path requires
   summing all `worker_epoch_grants[*]` per surplus acquire.
   At 6 workers and surplus-rate acquires ~5K/sec, that's ~30K
   atomic loads/sec/worker. Manageable, but if surplus is the
   common path under sustained saturation, this could become a
   hot fn. Alternative: maintain `class_total_granted` atomic
   updated on each primary/surplus grant. Trade: extra atomic
   per grant vs. O(N) sum per surplus acquire. Which is right?

3. **Epoch rotation jitter**: when the rotation winner is
   preempted between `compare_exchange` (claims rotation) and
   `epoch_start_ns.store` (publishes), peers see the new seq
   but old start_ns and might attempt second rotation. Bounded
   by the seq CAS — only one winner per seq increment — but
   what's the steady-state behavior under contention? Worst
   case: peers spin on `seq` mismatch waiting for `start_ns`
   publish. Probably fine; verify.

4. **Surplus overshoot bound**: stated as "bounded by per-
   acquire request size ≤ 48 KB". Is that actually true under
   N peers concurrently grabbing surplus? Worst case: all 6
   workers see `surplus_avail > 0` simultaneously, each grabs
   48 KB → 288 KB total grant for one acquire round. Bounded by
   one batch, but is the aggregate cap violated for ONE epoch
   before resetting?

5. **Work conservation argument**: "fast worker claims slow
   worker's unclaimed share via surplus". Verify the math:
   if A=fast and B=slow each have 50% share, and B serves only
   30% of share, A's surplus opportunity is 20% extra of share
   = 20% of total_cap × 0.5 = 10% of total_cap. So A serves
   60% of total_cap, B serves 30%, aggregate 90%. Or do we
   allow A to keep claiming surplus up to (total - sum), giving
   A = 70%, B = 30%, aggregate 100%? Both behaviors have
   merit; pick one and document.

6. **`max_worker_id` from the coordinator**: extending
   `matches_config` to include max_worker_id triggers lease
   rebuild on worker count change. What's the rebuild cost?
   Is rebuilding-during-traffic safe (frame inflight, queue
   non-empty)?

7. **Inter-worker time skew**: workers read `now_ns` at slightly
   different times (CLOCK_MONOTONIC RAW). Two workers could
   simultaneously see "epoch expired" and try to rotate. The
   seq CAS handles it. But could `epoch_start_ns` from worker
   A's perspective be "later" than worker B's perspective,
   leading to disagreement on which epoch's grants to use?
   Bounded by clock skew (~ns), but does it matter at 200µs
   epoch granularity?

8. **No `state.credits` for v3 callers**: v3 doesn't update
   `state.credits` or `outstanding_leased_tokens`. Existing
   `release_unused` calls (`token_bucket.rs:224`) become no-ops
   for v3 callers. Is that a leak? Or is `release_unused` only
   relevant for the legacy path?

9. **Window duration choice (200µs)**: matches existing refill
   cadence. At 16G class rate, that's 400 KB per epoch. Is
   that fine-grained enough for fairness signal? Or should it
   be 50µs (100 KB cap) for sharper convergence?

10. **TCP sender-side floor**: same caveat as v1/v2 reviews.
    iperf-c CoV expected ~21% (sender-side). v3's value is
    sub-saturation iperf-e style. Honestly disclosed.

---

## STOPPED state retained for reference

(The pre-v3 STOPPED status from 2026-05-07 is preserved below
for context. v3 supersedes.)

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
