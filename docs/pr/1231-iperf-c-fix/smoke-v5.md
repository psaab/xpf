# #1231 v5 cluster smoke results (commit 2d316bf2)

**Date:** 2026-05-08 (loss userspace cluster)
**Build:** `make build` clean; 1086 cargo tests pass.
**Deploy:** `cluster-setup.sh deploy all` succeeded; CoS re-applied.

## Pass A — CoS DISABLED

| Test | Throughput | Retrans |
|------|-----------|---------|
| v4 push 5201 | 7.30 Gbps | 0 |
| v6 push 5201 | 7.19 Gbps | 0 |
| v4 -P 12 -R 5201 | 22.9 Gbps | 337 |
| v6 -P 12 -R 5201 | 22.6 Gbps | 0 |

(Pass A CoS-off retrans on v4 is variance — not regression from v8;
v8 path doesn't activate without CoS.)

## Headline measurements (CoS ENABLED)

| Workload | Pre-v8 | v8 (PR #1230) | #1231 v5 | Target | Δ vs target |
|----------|--------|---------------|----------|--------|-------------|
| iperf-c push aggregate (12-stream, 25G EXACT) | 22.7G | 19.3G | **20.2G** | ≥22.0G | **-1.8G short** |
| iperf-c reverse aggregate | ~22G | 22.1G | 22.0G (4633 retrans) | ≥21G | flat |
| iperf-e per-flow CoV (12-stream, 16G EXACT) | 60% | **13.3%** | **21.7%** | ≤15% | **+6.7pp over** |
| iperf-e aggregate | 15.1G | 14.3G | 14.2G | flat | flat |

**Honest read:**

- **iperf-c push:** modest +0.9G recovery (19.3 → 20.2). Below the
  22.0G goal. Bypass IS firing but doesn't fully eliminate the v8
  grace-period throttle. Likely cause: workers at saturation
  consume whatever bypass grants them faster than the rotation
  cadence can re-arm; effective bypass is a fraction of epoch
  duration.

- **iperf-e CoV regression:** 13.3% → 21.7%. The narrow-signal +
  aggregate-underuse AND-gate is NOT tight enough. The 1-flow
  worker (worker E in [4,3,4,1]) gets a flow at ~1.78 Gbps; its
  primary share is 1/12 × 16G = 1.33 Gbps. So E exhausts primary,
  class room remains (cap is 16G, sum of grants below cap), grace
  closed → narrow signal fires → next rotation arms bypass.

  This is the false-positive Codex flagged in v2/v3 review. The
  aggregate-underuse gate (89% < 95% threshold) doesn't
  distinguish "iperf-c saturated" from "iperf-e shaper-bound but
  with one outlier flow above share".

- **iperf-c push retrans:** push had 2 retrans over 70.6 GB =
  0.000003%. Trivial.

- **iperf-c reverse retrans:** 4633 retrans over 76.7 GB =
  0.006%. Higher than v8's 0 retrans but still very low.

## Per-stream iperf-e detail

```
[ 5]:  911 Mbps    [ 7]:  909 Mbps    [ 9]: 1350 Mbps    [11]: 1780 Mbps  ← outlier
[13]: 1350 Mbps    [15]: 1360 Mbps    [17]: 1110 Mbps    [19]: 1110 Mbps
[21]:  911 Mbps    [23]: 1110 Mbps    [25]: 1360 Mbps    [27]:  911 Mbps
```

Range: 909 — 1780 Mbps. Max/min: 1.96×. Mean: 1181 Mbps. CoV: 21.7%.

The outlier flow [11] at 1780 Mbps is the single-flow worker E
exceeding its 1.33 Gbps primary share. Bypass arms via that
worker's signal.

## Conclusion

v5 implementation is correct per plan, but the false-positive
prediction from Codex's v2 review materialized. v8 fairness leaks
once any 1-flow worker has a flow above its 1/N share — which
happens whenever per-flow rate ≥ 1.33 Gbps on iperf-e (16G shaper
÷ 12 flows).

## Path forward options

**A. Tighten arm condition.** Require N% of active workers to
signal (e.g., ≥50%), not just any one. iperf-c [6,5,1] has only
1 worker signaling (C); iperf-e [4,3,4,1] has only 1 worker
signaling (E). Both fail the quorum, so bypass never arms either.
Loses the iperf-c recovery entirely.

**B. Tighten aggregate-underuse threshold.** Move from 95% to
75%. iperf-c at 19.3G/25G = 77% would still trigger; iperf-e at
14.2G/16G = 89% would not. But this only works if iperf-c
saturation post-v8 stays at 77% and iperf-e at 89%. Brittle.

**C. Different signal entirely.** The narrow-exit per-worker
signal can't distinguish "single-flow-CPU-bound" (we want to
fix) from "single-flow-shaper-bound" (we don't). Need a
fundamentally different mechanism, e.g., monitor the rate at
which the class CAS hits cap (the "all aggregate consumed,
some workers couldn't get primary share" regime). Not yet
designed.

**D. Accept v8 as merge state.** Close #1231 as "narrow-signal
detector PLAN-KILLED-by-empirics". Document that iperf-c push
saturated at -15% is the structural ceiling under v8.

## Recommendation

**D + new issue for option C.** v5 demonstrated the predicted
false-positive; the design space for narrow-signal distinguishers
is not yet promising. A class-cap-hit-rate signal is mechanically
different and warrants its own plan-review cycle (post-context
session likely).
