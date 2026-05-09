# #1231 v5.5 cluster smoke (peer-utilization gate)

**Date:** 2026-05-08, loss userspace cluster, recipe-doc env (sym
Toeplitz key + daemon CPU 0 pinning).

## What changed v5.5 vs v5

Added a third gate to bypass arming: **peer utilization**.

```rust
let mut any_peer_under_util = false;
for id in 0..n_workers {
    if !active_by_worker[id] || signaled_by_worker[id] { continue; }
    let share = ... worker_fair_share[id] ...;
    if share == 0 { continue; }
    // util < 60%: 5 * prev_grant < 3 * share
    if (prev_grants[id] as u64).saturating_mul(5) < share.saturating_mul(3) {
        any_peer_under_util = true;
        break;
    }
}
```

Bypass arms when **all three** conditions hold:
1. Any active worker signaled starvation (narrow exit).
2. Aggregate granted < cap × 0.95 (5% slack — restored from v5.1's 14%).
3. **Some active peer (not the signaling worker) consumed < 60% of its primary share.**

The peer-util gate is the discriminator. iperf-c saturation has
peers at <60% (CPU-bound below share); iperf-e shaper-bound peers
are at ~90% (close to share).

## 5-sample comparison (recipe knobs applied)

All numbers are 12-stream `iperf3 -P 12 -t 15 ... -p {5205|5203}`.

| Workload | v8 master | v5 (5% slack) | v5.1 (14% slack) | **v5.5 (peer-util)** |
|----------|-----------|---------------|------------------|----------------------|
| iperf-e CoV mean | 14.1% | 24.6% | 25.2% | **18.8%** |
| iperf-e CoV range | 7.9–21.6% | 8.9–35.1% | 13.8–38.7% | 14.2–27.9% |
| iperf-e aggregate | 14.18-14.36 G | 13.72-14.20 G | 14.16-14.37 G | 14.15-14.37 G |
| iperf-c push mean | 20.2 G | 20.1 G | 19.7 G | **20.9 G** |
| iperf-c push range | 18.6-21.4 G | 19.7-21.3 G | 17.4-21.1 G | 19.7-21.4 G |

**Verdict: v5.5 is a measurable but modest improvement.**

- **iperf-c push:** +0.7G mean (20.2 → 20.9), with 4 of 5 samples at
  21.2-21.4 G (consistent recovery in most epochs). Still below
  pre-v8 baseline (recipe doc reports 22.7G with all knobs, but this
  isn't reproducible in current cluster state — even v8 alone is at
  20.2G mean).
- **iperf-e CoV:** mean 18.8%, range 14.2-27.9%. Above v8's 14.1%
  mean and target ≤15%. The peer-util gate reduces false-positive
  rate vs v5/v5.1 but doesn't eliminate it — iperf-e samples occasionally
  trigger bypass when sample variance puts a peer below 60% util by chance.

## Why v5.5 is the best of the 4 iterations

| | v5 | v5.1 | v5.5 |
|-|-|-|-|
| iperf-e CoV regression vs v8 | +10.5pp | +11.1pp | **+4.7pp** |
| iperf-c push improvement vs v8 | -0.1G | -0.5G | **+0.7G** |

v5.5 is the only iteration that BOTH improves iperf-c AND has minimal
iperf-e regression.

## Honest read

- **The "iperf-c push -15% regression" the original #1231 issue cites
  may not exist in the current cluster.** v8-only baseline measured
  here at 20.2G mean across 5 samples, vs pre-v8 22.7G claimed in
  recipe doc. The actual regression is closer to -11% (2.5G gap), not
  -15%, OR the current cluster has drifted vs PR #1230's measurement
  conditions.
- **v5.5 recovers ~28% of that gap** (+0.7G of the 2.5G).
- **iperf-e CoV cost is real** (+4.7pp mean) but bounded.
- Multi-sample harness (#1232) and CoS-runtime debug (#1234) are
  prerequisites for confident merge.

## Recommendation

v5.5 represents the best balance achievable with the bypass-grace
detector design. It does not fully recover iperf-c (architectural
limit: peer-util gate is necessary but not sufficient when iperf-e
also has occasional peer-util dips). Further iteration would need a
different mechanism (e.g., #1233 sender-side TCP fix or a v6 design
with per-class regime memory).

Trade-off summary:
- iperf-c push: +0.7G (modest)
- iperf-e CoV: +4.7pp (modest cost)
- Net: marginal improvement; merge-or-no decision is judgment call.
