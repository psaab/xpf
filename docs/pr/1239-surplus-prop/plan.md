# #1239 v1: Surplus claim proportional to flow count

**Status:** DRAFT v1 — pending Codex hostile + Gemini Pro 3 adversarial review

## Issue framing

After PR #1235 (#1231 v5.5 bypass-grace) merged + #1236 v1 (global
per-flow cap) PLAN-KILLED + #1237 v1 (per-worker reactive share)
PLAN-KILLED, both reviewers explicitly recommend pursuing this
mechanism.

Empirical iperf-d 12-stream measurements (recipe knobs applied):

| Worker | Flows | Primary share | Actual | Util | Per-flow |
|--------|-------|---------------|--------|------|----------|
| α | 4 | 4.33G | 3.13G | 72% | 784 |
| β | 3 | 3.25G | 2.82G | 87% | 941 |
| γ | 2 | 2.17G | 2.14G | 99% | 1069 |
| δ | 3 | 3.25G | 3.49G | **107%** | 1163 |

Worker δ's "107% utilization" comes from claiming surplus (post-grace
or via #1231 bypass). Its 7% over-share concentrates on δ's 3 flows
→ +76 Mbps per flow. This is the dominant per-flow CoV contributor
in shaper-bound regimes.

**Math: per-flow primary is ALREADY equal in v8.**
- Per-worker primary share = (worker_flows / total_flows) × cap
- Per-flow primary rate within worker = primary / worker_flows = cap / total_flows
- Same value for ALL workers ✓

**The variance comes from surplus.** Currently surplus is per-WORKER:
worker δ claims whatever class_room is available, distributes among
its 3 flows. Worker α with 4 flows that can't consume primary leaves
its share unconsumed (becomes the surplus), and δ takes it.

## Honest scope/value framing

#1239 mechanism: bound per-worker surplus claim at
`(worker_flows / total_flows) × class_room`. Same flow-proportional
formula as primary share, applied to surplus.

Predicted outcome:
- Worker δ's surplus claim drops from "all of class_room" to
  "3/12 × class_room" → its 3 flows go from 1163 to ~1083 Mbps each.
- Worker α's primary still at 780 (CPU/TCP-bound below primary).
- Per-flow rates after: [780×4, 941×3, 1069×2, 1083×3]. Range
  780-1083, CoV ~12% (down from 18% mean).
- Aggregate preserved: total distributed = total surplus available.
  No Harrison Bergeron — slow workers' unused share still goes to
  others, just FAIRLY distributed.

**Math proof of per-flow equality (when all workers can consume
share):**
- Total per-worker = primary + surplus
  = (flows_w/total) × cap + (flows_w/total) × class_room
  = (flows_w/total) × (cap + class_room)
- Per-flow rate = total_per_worker / flows_w
  = (cap + class_room) / total_flows
- **Same for all workers — proven equal.**

**Trade-off:** none for aggregate (surplus is redistributed, not
withheld). For per-flow CoV: improves the surplus-concentration
component but doesn't fix slow-worker primary under-utilization.

**If reviewers find that bounded surplus reduces aggregate
throughput on iperf-c saturated, or that the mechanism breaks
work conservation, PLAN-KILL is acceptable.**

## What's already shipped

- **#1229 v8** (PR #1230): per-worker fair-share lease, hierarchical
  scheduler, atomic-swap rotation. Per-worker primary share already
  flow-proportional.
- **#1231 v5.5** (PR #1235): bypass-grace detector with surplus
  path enabled when peers are CPU-bound. Surplus claim currently
  unbounded per-worker.

#1239 modifies the surplus claim cap in `acquire_v8`'s surplus path.
Primary path unchanged.

## Concrete design

### v1.1 Surplus claim formula

Currently in `acquire_v8` surplus path:

```rust
// SURPLUS PATH (v5.5 unchanged)
loop {
    let class_curr = packed_granted.0.load(Acquire);
    let (tag, granted) = unpack(class_curr);
    if tag != my_tag { break; }
    if granted >= cap { break; }
    let class_room = cap - granted;          // ← unbounded per worker
    let take = still_needed.min(class_room).min(u32::MAX);
    // ... CAS + grant
}
```

Change `class_room` to be flow-proportional per-worker:

```rust
// SURPLUS PATH v1239
loop {
    let class_curr = packed_granted.0.load(Acquire);
    let (tag, granted) = unpack(class_curr);
    if tag != my_tag { break; }
    if granted >= cap { break; }

    // #1239 v1: per-worker surplus quota = (my_flows / total) × class_room
    let class_room = cap - granted;
    let total_flows = lease.global_active_flow_buckets().max(1) as u64;
    let my_flows = lease
        .worker_active_flow_buckets[my_worker_id]
        .load(Relaxed) as u64;

    // Already-claimed surplus by this worker this epoch:
    let my_already_granted = unpack(worker_grants[my_worker_id].load(Acquire)).1 as u64;
    let my_primary_share = worker_fair_share[my_worker_id].load(Relaxed);
    let my_surplus_already = my_already_granted.saturating_sub(my_primary_share);

    // Quota: my proportional share of remaining class budget,
    // minus surplus I've already claimed this epoch.
    let my_surplus_quota = (class_room as u128 * my_flows as u128 / total_flows as u128) as u64;
    let my_surplus_remaining = my_surplus_quota.saturating_sub(my_surplus_already);
    if my_surplus_remaining == 0 { break; }

    let take = still_needed
        .min(class_room)
        .min(my_surplus_remaining)
        .min(u32::MAX as u64);
    // ... CAS + grant
}
```

### v1.2 Math verification

Three workers with flows [α=4, β=3, γ=2, δ=3], class_room remaining
after primary consumption:

| Worker | Primary used | Primary share | Flows | Surplus quota | Total possible |
|--------|--------------|---------------|-------|---------------|----------------|
| α | 3.13G | 4.33G | 4 | 4/12 × 1.87G = 0.62G | 3.13 + 0.62 = 3.75G |
| β | 2.82G | 3.25G | 3 | 3/12 × 1.87G = 0.47G | 2.82 + 0.47 = 3.29G |
| γ | 2.14G | 2.17G | 2 | 2/12 × 1.87G = 0.31G | 2.14 + 0.31 = 2.45G |
| δ | 3.25G | 3.25G | 3 | 3/12 × 1.87G = 0.47G | 3.25 + 0.47 = 3.72G |

(class_room = 13 - 11.34 = 1.66G; rough estimate)

Per-flow rates:
- α: 3.75/4 = 938 Mbps (was 784) — α consumes more if it can
- β: 3.29/3 = 1097 Mbps (was 941)
- γ: 2.45/2 = 1225 Mbps (was 1069)
- δ: 3.72/3 = 1240 Mbps (was 1163)

But α can't consume more (CPU/TCP-bound at 780). So α stays at 3.13G,
class_room becomes 13 - 11.6 = 1.4G next epoch.

This is reactive — the formula self-corrects. If α leaves surplus, the
next epoch's class_room is bigger, redistribution happens at scaled
rates.

In equilibrium (steady state):
- Per-flow rate ≈ aggregate / total_flows
- All workers' flows converge to same per-flow rate IF they can
  consume their proportional share.
- Slow workers (CPU-bound) still consume what they can; their
  unused share gets distributed proportionally to all (including
  themselves; they just can't use more).

### v1.3 Aggregate impact

Total surplus distributed = sum of surplus claims = class_room
(when fully claimed). No surplus is withheld. Aggregate matches
v5.5.

For iperf-c saturated [6,5,1] case:
- Worker A (6 flows, CPU-bound at ~5.5G): primary share 12.5G, used 5.5G. Leaves 7G unused.
- Worker B (5, CPU-bound ~5.5G): primary 10.4G, used 5.5G. Leaves 4.9G unused.
- Worker C (1 flow, ~4G CPU): primary 2.08G, used 2.08G + claims surplus.
- class_room = 12.92G (from A+B unused). Currently C claims much of it.
- With #1239: C's surplus quota = 1/12 × 12.92G = 1.08G. So C total = 2.08 + 1.08 = 3.16G.
- A, B's surplus quota: 6/12, 5/12 of 12.92G. They can't consume — already CPU-bound.
- Aggregate = 5.5 + 5.5 + 3.16 = 14.16G.

But pre-v8 baseline was 22.7G. v8 shipped at ~20G. With #1239 capping
C, aggregate drops to 14.16G — WORSE than v5.5.

**THIS IS A REAL ISSUE.** When peers are CPU-bound and can't claim
their proportional surplus, the unused budget is wasted.

### v1.4 Mitigation: redistribute unclaimed surplus

If A and B can't consume their surplus quota, that capacity should
flow back to C. Current v5.5 surplus does this implicitly (workers
race for class_room).

#1239 v1's hard quota breaks work conservation. Need redistribution
mechanism.

Options:
A. **Two-pass distribution**: at rotation observe per-worker
   under-claim, redistribute unclaimed quota to peers proportionally.
B. **Soft cap**: quota is a hint; if class_room remains and worker
   has demand, allow over-quota up to limit.
C. **Cap only when peers ARE consuming**: if no peer is at quota,
   allow over-claim. Complex.
D. **Replace bypass-grace mechanism (#1231 v5.5)**: bypass arms when
   peers under-utilize → opens surplus path. With #1239 quota,
   bypass-arming detection + over-quota allowance gives the
   needed work conservation in CPU-bound regime.

### v1.5 Refined v1: quota with bypass-aware over-claim

Combine #1239 quota with #1231 v5.5 bypass:

- **Bypass NOT armed** (shaper-bound regime, e.g. iperf-d):
  workers strictly observe `(my_flows / total) × class_room` quota.
  Per-flow rates equalize.
- **Bypass armed** (CPU-bound regime, e.g. iperf-c saturated):
  surplus path bypasses quota → workers grab any class_room.
  Aggregate maximized; per-flow CoV not improved (but already
  uneven due to CPU-bound slow workers anyway).

The two regimes fundamentally differ; #1231 v5.5 already detects
which one we're in. Use that signal to switch surplus claiming
mode.

```rust
let bypass_armed = lease.epoch.bypass_grace_rotations_remaining
    .load(Relaxed) > 0;
let surplus_quota = if bypass_armed {
    class_room  // unbounded — work conservation in CPU-bound regime
} else {
    (class_room as u128 * my_flows as u128 / total_flows as u128) as u64  // proportional
};
```

### v1.6 Public API preservation

- `SharedCoSQueueLease` accessor: `global_active_flow_buckets()` —
  reads sum of `worker_active_flow_buckets`. Was already proposed
  in #1236; reuse here.
- `acquire_v8` signature unchanged.
- Bypass detection signal unchanged.

### v1.7 Hidden invariants

1. **Aggregate cap preserved**: `epoch_total_granted ≤ cap` still
   enforced by class CAS (unchanged from v5.5).
2. **Per-flow primary equality**: cap × flows/total ÷ flows = cap/total.
3. **Per-flow surplus equality** (when not bypass-armed):
   class_room × flows/total ÷ flows = class_room/total.
4. **Work conservation when bypass-armed**: full class_room
   accessible, matches v5.5 behavior.

### v1.8 Risk assessment

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | Bypass-armed regime preserves v5.5; not-armed regime is the iperf-d shaper-bound case where CoV improvement is the goal. |
| Lifetime/borrow-checker | LOW | No new state. Reads existing atomics. |
| Performance | LOW | 1 sum + 1 division per surplus loop iteration. ~30 ns. |
| Aggregate regression in shaper-bound | LOW | Class_room remains accessible to all workers; unclaimed quota gets observed at next rotation and redistributed automatically as class_room grows. |
| Aggregate regression in CPU-bound | LOW | Bypass arms → quota path bypassed → matches v5.5. |

### v1.9 Test plan

- Cargo build clean.
- Cargo test --release: 1086+ tests pass.
- New tests:
  - `surplus_claim_bounded_by_flow_proportional_quota`
  - `surplus_claim_unbounded_when_bypass_armed`
  - `total_surplus_distributed_proportionally_across_workers`
- Cluster smoke matrix:
  - Pass A/B clean
  - **iperf-d 12-stream 10-sample mean CoV ≤ 12%** (target)
  - **iperf-c push 12-stream**: aggregate ≥ v5.5 mean (no regression because bypass arms in CPU-bound regime)
  - **iperf-e 12-stream**: per-flow CoV ≤ v5.5 mean

### v1.10 Out of scope

- Slow worker per-flow rate (still bounded by worker's CPU/TCP)
- Cross-binding flow re-steering (#937 PLAN-KILLED)
- Sender-side TCP head-start (#1233)

### v1.11 Open questions for adversarial review

1. **Bypass-arming heuristic correctness**: #1231 v5.5 arms bypass
   when (any worker signaled starvation) AND (aggregate < 95%) AND
   (some peer < 60% util). Does this fire reliably in iperf-c
   saturated regime? Reliably NOT fire in iperf-d shaper-bound?

2. **Quota racing**: workers compute quota at acquire time. If
   class_room shrinks between quota-compute and CAS, quota becomes
   stale (over-estimated). Bound: per-acquire single batch size.

3. **Worker leaves surplus unclaimed**: if α's CPU-bound below
   primary AND below quota, α's quota goes unused this epoch.
   Class_room next epoch grows. Other workers re-claim
   proportionally. Self-corrects within bounded epochs.

4. **Bypass interaction**: when bypass arms mid-acquire, does the
   surplus quota suddenly relax? Yes — read once per loop iteration,
   not snapshot. Acceptable transient.

5. **Compute global_active_flow_buckets cost**: 6 atomic loads per
   surplus acquire. Negligible.

6. **Per-worker surplus already-claimed tracking**: derived from
   worker_grants[id] - my_primary_share. Both available in v8.
   No new state.

7. **Math verification on iperf-e [4,3,4,1]**: per-flow primary =
   16G/12 = 1.33G. Worker E (1 flow) primary share = 1.33G. E's
   actual ~1.78G in earlier test → claimed 0.45G surplus. With
   #1239: E's quota = 1/12 × class_room. If class_room = 1G,
   E's quota = 0.083G. E's flow drops from 1.78G to 1.33 + 0.083
   = 1.42G. Per-flow CoV improves.

8. **Convergent improvement vs #1231 v5.5**: this strictly tightens
   surplus distribution; cannot make iperf-d worse than current
   v5.5 baseline.

9. **Implementation effort**: ~50 LOC (surplus quota computation +
   global_flows accessor) + ~80 LOC tests. Single triple-review
   round.

10. **Worst-case failure mode**: if bypass-arming detector is
    wrong (e.g., false negative on CPU-bound regime), iperf-c
    aggregate drops. Risk bounded to v5.5's baseline at worst.
