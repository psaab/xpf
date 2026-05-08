# #1229 Phase 5 cluster smoke results

**2026-05-07.** loss userspace cluster, master + 1229 v7 implementation
(commits 2975b394 → de5dd54c on `1229-cross-worker-vtime`).

## User's exact command (no workload-side knobs)

```bash
iperf3 -c 2001:559:8585:80::200 -P 12 -t 30 -p 5205
```

## Per-stream Mbps comparison

| | Baseline (master) | #1229 v7 Phase 4 |
|---|---|---|
| s_15 | (varied) | 952 |
| s_07 | (varied) | 953 |
| s_11 | (varied) | 978 |
| s_27 | (varied) | 996 |
| s_25 | (varied) | 1010 |
| s_21 | (varied) | 1011 |
| s_17 | (varied) | 1103 |
| s_05 | (varied) | 1108 |
| s_19 | (varied) | 1138 |
| s_13 | (varied) | 1145 |
| s_09 | (varied) | 2216 |
| s_23 | (varied) | 2408 |

User's earlier baseline capture from this thread:
```
478, 479, 481, 482, 1147, 1152, 1171, 1179, 1569, 1583, 2203, 3132 Mbps
```

## Computed metrics

| | Baseline | Phase 4 |
|---|---|---|
| min | 478 | 952 |
| max | 3132 | 2408 |
| spread (max/min) | 6.55× | 2.53× |
| **observed_cov** | **~0.59** | **~0.37** |

**38% per-flow CoV reduction.** 10 of 12 streams now cluster tightly
at 950-1150 Mbps; 2 outliers remain (2200-2400 Mbps).

## Gap analysis: why not below 0.10

The local cap formula is:
```
target_bps = transmit_rate / max(1, active_flow_buckets)
```

`active_flow_buckets` is the local-worker count of active buckets.
A worker with 4 active flows computes `target = 16G/4 = 4G/bucket`.
A worker with 1 active flow computes `target = 16G/1 = 16G/bucket`.

Result: workers with fewer flows have higher per-flow allowance,
so their flows can race to higher rates than flows on heavily-loaded
workers. The `SharedCoSQueueLease` should redistribute, but at
saturation it caps total throughput per class — it doesn't actively
re-equalize per-flow rates.

## What would close the remaining gap

A **global** denominator: total active flows across all workers
in the same forwarding class. Each worker reads
`PerClassFairnessState.total_active_flows.load()` (Arc-shared,
updated at the ~65ms publish tick) and uses that:

```
target_bps = class_rate / max(1, total_active_flows)
```

Where `total_active_flows = Σ per_worker_active_buckets`.

This was the v3 design (`PerClassFairnessState` Arc plumbed through
`coordinator/cos_state.rs` + `worker/cos.rs`), which both round-5
reviewers convinced me to drop in favor of the local denominator
on grounds that `SharedCoSQueueLease` would propagate fairness.
Empirically that propagation isn't enough at saturation.

## Recommendation

**Phase 6 (follow-on PR)**: re-introduce `PerClassFairnessState` as
v3 originally proposed. Specifically:

1. Add `Arc<PerClassFairnessState>` to `CoSQueueConfigState` per
   `(egress_ifindex, queue_id)`.
2. Plumb through `coordinator/cos_state.rs` →
   `WorkerCoSQueueFastPath` → `CoSQueueConfigState.shared_fairness`
   following the V_min floor pattern at `worker/cos.rs:113` +
   `admission.rs:490`.
3. Update `compute_drain_target_bps` to read
   `total_active_flows.load()` instead of the local
   `active_flow_buckets`.

Estimate: ~80 LOC + plumbing tests. Should close the remaining
0.37 → ≤0.10 CoV gap empirically.

## Phase 4 verdict

**Substantial empirical improvement (60% → 37% CoV)** with the
local-only cap. Ships independently of Phase 6 because:

- Real measurable benefit on the user's exact workload.
- No regression in any of 1065 unit tests.
- Foundation infrastructure in place for the global-denominator
  follow-on (rate tracking + cap-aware selector + 4 commit-path
  wiring all done).

Phase 6 is incremental scope. Phase 4 stands alone.
