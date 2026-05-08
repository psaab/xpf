# Phase 5 cluster smoke — UPDATED with re-test (sym key + daemon pinning re-applied)

After daemon restart following Phase 4 deploy, the symmetric Toeplitz key
and daemon CPU pinning had reverted (key reset by NIC reinit, pinning
reset by xpfd restart since `taskset -pc` is per-PID). Re-applied both
and re-ran the user's exact command:

```bash
iperf3 -c 2001:559:8585:80::200 -P 12 -t 30 -p 5205
```

Per-stream Mbps with all knobs (sym key + daemon pin + Phase 4 cap):
```
715, 716, 718, 719,    (4 streams clustered)
1366, 1377,            (2 streams clustered)
1567, 1567, 1570, 1575, 1579, 1586  (6 streams clustered tightly)
```

Aggregate: 15.06 Gbps (just under iperf-e 16G shaper).

Three flow-rate clusters of 4 / 2 / 6 streams — likely corresponding to
how the symmetric Toeplitz hash distributed the 12 ephemeral source
ports onto worker queues with different `active_flow_buckets` counts.

Computed CoV ≈ **0.31**. Versus user's earlier baseline capture
(478, 479, 481, 482, 1147, 1152, 1171, 1179, 1569, 1583, 2203, 3132 —
CoV ≈ 0.59), this is a **48% reduction** in per-flow CoV.

## Why not lower

The local-worker cap denominator `transmit_rate / active_flow_buckets`
varies per worker. A worker with 6 active buckets computes a cap of
2.67 Gbps/bucket; a worker with 2 active buckets computes 8 Gbps/bucket.
The 6-bucket worker's flows can each hit ~1.5 Gbps (well below 2.67G
cap). The 4-bucket worker's flows are CPU-bottlenecked at ~717 Mbps
(also below their 4G cap). The cap isn't binding in either case —
flow rates differ because the **workers** run at different rates, and
the per-worker cap can't equalize across.

## Phase 6 is what closes the remaining gap

Replace the per-worker `active_flow_buckets` denominator with the
**global sum across workers**: `transmit_rate / total_active_flows`.
Each worker computes the same target → each flow gets the same fair
share regardless of which worker it landed on.

Implementation requires `Arc<[AtomicU32; MAX_WORKERS]>` per
`(egress_ifindex, queue_id)`, plumbed via the same pattern as
`SharedCoSQueueVtimeFloor` (`coordinator/cos_state.rs:13`). Each
worker writes its own slot at the existing ~65ms tick; reads the
sum at drain start. ~80 LOC + integration + tests.

This was the v3 design (`PerClassFairnessState`) that round-5 reviewers
convinced me to drop in favor of the local denominator. Empirical
data shows the local denominator is insufficient; Phase 6 closes the
gap.

## Phase 4 ships standalone

48% CoV reduction is real measurable progress. Phase 6 is the
incremental follow-on to close the remaining 0.31 → ≤0.10 gap.
