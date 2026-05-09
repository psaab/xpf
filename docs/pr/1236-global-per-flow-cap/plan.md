# #1236 v1: Global per-flow rate cap for shaped multi-stream workloads

**Status:** DRAFT v1 — pending Codex hostile + Gemini Pro 3 adversarial review

## Problem framing

PR #1235 (#1231 v5.5 bypass-grace detector merged) addresses
cross-class CPU-bound saturation. But on shaped intra-class
workloads, per-flow throughput remains uneven:

iperf-d (port 5204, 13G EXACT shaper, 12 streams, recipe knobs
applied):

```
[720, 720, 720, 720, 720, 1085, 1085, 1104, 1104, 1139, 1140, 1350]
sum=11.61G  CoV=23.7%  max/min=1.88x
```

Decomposition by worker (RSS-derived [5, 3, 2, 2] flow distribution):

| Worker | Flows | Share | Actual | Util | Per-flow |
|--------|-------|-------|--------|------|----------|
| A      | 5     | 5.42G | 3.6G   | 67%  | 720 Mbps |
| B      | 3     | 3.25G | 2.85G  | 88%  | 950 Mbps |
| C      | 2     | 2.17G | 2.18G  | 100% | 1090 Mbps |
| D      | 2     | 2.17G | 2.74G  | 126% | 1370 Mbps |

Worker A is CPU-bound (worker 0 shares CPU 0 with daemon
control-plane threads); its per-flow rate caps at ~720.
Worker D claims surplus from A/B's underutilized share via
post-grace path → its 2 flows get 1370 each.

The current cap-aware MQFQ (Phase 6 v8 #1229) caps each bucket
at `transmit_rate / active_flow_buckets`, but `active_flow_buckets`
is **per-worker** — so Worker D's cap is `13G / 2 = 6.5 G` per
flow, way above its actual 1370. Cap doesn't bind.

## Honest scope/value framing

v6 makes ALL workers cap each flow at the GLOBAL fair share:
`transmit_rate / total_global_active_flow_buckets`. For iperf-d:
target = 13G / 12 = **1083 Mbps per flow**.

Predicted outcome:
- Worker D's flows capped at 1083 (was 1370): -287 Mbps each.
- Worker A's flows below cap (720): no change.
- Worker B/C below cap: no change.

Predicted aggregate: 5×720 + 3×950 + 2×1083 + 2×1083 = **10.78 G**
(~7% loss from current 11.61G).

Predicted per-flow rates: [720×5, 950×3, 1083×2, 1083×2]. Range
720-1083, max/min = 1.50x. CoV ≈ 13-15%.

**Trade-off:** ~7% aggregate loss for CoV reduction from 24% → 14%.
The slow worker remains the bottleneck for its 5 flows; we cap the
fast workers down to its level.

**If reviewers conclude the aggregate loss outweighs the CoV win, or
if the global cap mechanism breaks intra-class fairness on simpler
distributions, PLAN-KILL is acceptable.**

## What's already shipped

- **Phase 6 v8** (#1229, PR #1230): cap-aware MQFQ with PER-WORKER
  target. Plus per-worker fair-lease via SharedCoSQueueLease.
- **#1231 v5.5** (PR #1235): bypass-grace detector for cross-class
  CPU-bound regime. Peer-utilization gate at 60%.

The cap-aware MQFQ infrastructure is reusable. v6 just changes the
target denominator from per-worker to global.

## Concrete design

### 1. Global active flow bucket counter

Already exists: `lease.worker_active_flow_buckets` is per-worker;
sum across workers gives global count.

Add an accessor:

```rust
impl SharedCoSQueueLease {
    pub(in crate::afxdp) fn global_active_flow_buckets(&self) -> u32 {
        self.v8.as_ref()
            .map(|v8| v8.worker_active_flow_buckets.iter()
                .map(|c| c.load(Ordering::Relaxed))
                .sum())
            .unwrap_or(0)
    }
}
```

### 2. Compute global target_bps in drain.rs

Currently `compute_drain_target_bps` returns
`transmit_rate / active_flow_buckets` (per-worker). v6 changes to
GLOBAL when a v8 lease is attached:

```rust
fn compute_drain_target_bps(queue: &CoSQueueRuntime) -> u64 {
    let Some(ff) = queue.flow_fair_state.as_ref() else { return u64::MAX; };
    let rate_bytes = queue.config.transmit_rate_bytes;
    if rate_bytes == 0 { return u64::MAX; }
    let queue_bw_bps = (rate_bytes as u128).saturating_mul(8) as u64;

    // v6: prefer global denominator if v8 lease attached.
    let denom = if let Some(lease) = queue.queue_lease_v8.as_ref() {
        let global = lease.global_active_flow_buckets();
        if global > 0 { global as u64 } else { ff.active_flow_buckets.max(1) as u64 }
    } else {
        ff.active_flow_buckets.max(1) as u64
    };
    queue_bw_bps / denom
}
```

When a worker has more flows than the global denominator implies
(e.g., A with 5 flows on a 12-flow class → A's per-flow target =
13G/12 = 1083 Mbps), the cap is the GLOBAL target. Worker A's
flows can each consume up to 1083 if A's CPU permits.

When a worker has fewer flows (e.g., D with 2 flows on a 12-flow
class), each of D's flows is capped at 1083 even if D's
per-worker share would let it go higher.

### 3. No changes to acquire_v8 / lease accounting

The lease's per-worker fair share continues to enforce class budget
distribution. The MQFQ selector with global target_bps just
prevents fast workers' flows from running over the global per-flow
fair rate, redirecting their drain attempts to the lowest-finish
bucket (still work-conserving — within-bucket round-robin
preserved).

### 4. Telemetry

Add an accessor to expose the active global denominator (for
operator visibility):

```rust
pub(in crate::afxdp) fn v8_global_active_flow_buckets(&self) -> u32 {
    self.v8.as_ref()
        .map(|v8| v8.worker_active_flow_buckets.iter()
            .map(|c| c.load(Ordering::Relaxed)).sum())
        .unwrap_or(0)
}
```

Surface via Prometheus `xpf_cos_v8_global_active_flow_buckets{queue}`.

## Public API preservation

- `compute_drain_target_bps` is internal (`pub(in crate::afxdp)`).
  Signature unchanged.
- New accessor `global_active_flow_buckets()` on
  `SharedCoSQueueLease`. Internal to `afxdp` module.
- No changes to acquire_v8, rotation, or fairness invariants.

## Hidden invariants

1. **Cap monotonic in global flow count**: as flows enter/leave,
   denominator changes; cap shifts. Within an epoch this is
   bounded — cap stays at one value during the rotation snapshot.
2. **Aggregate ≤ shaper**: cap × global_count ≤ class_rate (by
   construction). Aggregate cannot exceed shaper.
3. **Work conservation**: `cos_queue_min_finish_bucket` falls back
   to lowest-finish bucket if all are over-cap. So if all flows
   are CPU-bound below cap, no flow is throttled. (For iperf-d
   case: A's flows under 1083 cap, B's under 1083 cap. Only D's
   flows hit cap.)
4. **No cross-worker race**: per-bucket EWMA observed_bps is
   single-writer-per-worker (already invariant from #1229 Phase 6).

## Risk assessment

| Class | Severity | Notes |
|-------|----------|-------|
| Behavioral regression | LOW | cap-aware MQFQ infra exists; v6 just changes denominator. Fall-back to lowest-finish bucket preserves work conservation. |
| Lifetime/borrow-checker | LOW | New accessor reads existing atomics. No new state. |
| Performance regression | LOW | Per-acquire: 1 extra atomic read per worker × N workers (sum) computed once per drain batch. Cost ~30 ns at 6 workers. |
| Aggregate regression | MED | ~7% predicted loss on iperf-d. Could be larger on workloads where ALL flows are above the global cap. Validate empirically. |
| Cross-class interference | LOW | v6 is per-class; doesn't interact with cross-class scheduling. |

## Test plan

- Cargo build clean.
- Cargo test --release: 1086+ tests pass.
- New tests: global_active_flow_buckets returns correct sum;
  compute_drain_target_bps uses global denom when v8 lease attached.
- Cluster smoke matrix on loss userspace cluster:
  - **Pass A** (CoS off): no regression.
  - **Pass B** (24 per-class): per-class throughput must stay
    within 10% of v5.5.
  - **iperf-d 12-stream**: CoV ≤ 15% (target);
    aggregate ≥ 10.5 G (≥80% of shaper).
  - **iperf-e 12-stream**: per-flow CoV no worse than v5.5's 18.8%
    mean.
  - **iperf-c push 12-stream**: aggregate ≥ 19 G (within 10% of
    v5.5's 20.9G).

## Out of scope

- Cross-binding flow re-steering (#937 PLAN-KILLED).
- Per-flow EWMA rate enforcement at the per-packet level (would
  require a different mechanism; cap-aware MQFQ is per-bucket).
- Sender-side TCP head-start (#1233).

## Open questions for adversarial review

1. **Global target_bps stability**: as flows churn,
   `global_active_flow_buckets` changes. Workers see different
   targets at different rotation snapshots. Bounded by
   EPOCH_DURATION_NS. Acceptable?

2. **Aggregate loss prediction**: 7% on iperf-d. Worst case?
   Walk through degenerate distributions (e.g. all flows on 1
   worker, vs perfectly balanced).

3. **Interaction with bypass (#1231 v5.5)**: bypass opens surplus
   path immediately when armed. With global per-flow cap, surplus
   acquires would still be per-bucket-cap-aware. Does bypass
   conflict with global cap?

4. **Per-worker share enforcement still happens?**: the lease's
   `acquire_v8` enforces per-worker primary share. If global cap
   throttles a worker below its share, does that leave class
   budget unconsumed? Or does the unused per-worker share become
   surplus that other workers (with under-cap flows) can claim?

5. **iperf-c push impact**: at saturation [6,5,1] flow distribution.
   Per-flow targets:
   - global: 25G/12 = 2083 Mbps
   - Worker A's 6 flows currently at ~2083 Mbps (?), no change
   - Worker C's 1 flow at ~3000+ Mbps (?), capped at 2083
   - Aggregate may decrease. Quantify.

6. **iperf-e CoV impact**: at 16G shaper, 12 flows, target =
   1333 Mbps. Currently flows at 909-1780 (max above cap).
   Cap engages on outlier → CoV improves? Or does it just shift
   variance?

7. **Skew across classes**: applies per-class. Different classes
   can have different global denoms simultaneously. No
   cross-class interaction. Confirmed.

8. **What if global is 0** (no active flows)? Default fallback
   handles. Verify.

9. **MQFQ fall-back behavior**: when ALL buckets are over-cap,
   `cos_queue_min_finish_bucket` falls back to lowest-finish.
   Means cap is advisory under sustained over-cap conditions.
   Is that correct semantics?

10. **Code review-readiness**: is the diff small enough to merge
    after a single round of triple review? ~30 LOC + tests.

## Implementation effort

~30 LOC core (drain.rs target computation + lease accessor) +
~80 LOC tests + smoke validation. ~2 hours focused work.
