# #1229 Phase 6 v8 — cluster smoke results

**Date:** 2026-05-08 (loss userspace cluster, master HEAD = 7ac1b36f)
**Build:** `make build` clean; `cargo test --release` 1077 pass
**Deploy:** `BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
./test/incus/cluster-setup.sh deploy all` succeeded; CoS config
re-applied via `apply-cos-config.sh loss:xpf-userspace-fw0`.

## Pass A: CoS DISABLED (best-effort fast path)

Tear-down sequence:
- `delete class-of-service`
- `delete firewall family inet/inet6 filter bandwidth-output`
- `delete interfaces reth0 unit 80 family inet/inet6 filter output`
- `commit check && commit`

| Test | Throughput | Retrans |
|------|-----------|---------|
| v4 push 5201 | 7.13 Gbps | 0 |
| v4 rev 5201 | 7.53 Gbps | 0 |
| v6 push 5201 | 7.26 Gbps | 0 |
| v6 rev 5201 | 7.31 Gbps | 0 |
| **v4 -P 12 -R 5201** | **22.9 Gbps** | **0** |
| **v6 -P 12 -R 5201** | **22.5 Gbps** | **0** |

**Verdict:** Pass A clean. No regression in the unshaped fast path —
v8 modifications are confined to Guarantee-phase exact queue lease,
which is not in play when CoS is disabled.

## Pass B: CoS ENABLED — per-class smoke (5201-5206)

CoS config applied via `apply-cos-config.sh`. All classes shaped per
configured rate.

| Class | Rate | v4 push | v4 rev | v6 push | v6 rev | Retrans |
|-------|------|---------|--------|---------|--------|---------|
| iperf-a | 1G | 834 Mbps | 5.82 Gbps | 831 Mbps | 5.85 Gbps | 0 |
| iperf-b | 10G | 5.65 Gbps | 6.96 Gbps | 5.51 Gbps | 6.93 Gbps | 0 |
| iperf-c | 25G | 5.90 Gbps | 7.03 Gbps | 6.08 Gbps | 7.11 Gbps | 0 |
| iperf-d | 13G | 6.18 Gbps | 6.08 Gbps | 6.04 Gbps | 6.75 Gbps | 0 |
| iperf-e | 16G | 6.15 Gbps | 6.90 Gbps | 6.15 Gbps | 6.87 Gbps | 0 |
| iperf-f | 19G | 6.27 Gbps | 6.89 Gbps | 6.26 Gbps | 6.84 Gbps | 0 |

iperf-a push hits its 1G shaper; reverse is unshaped at ~5.8G.
Other classes all in the 5.5-7.1 Gbps band consistent with single-
stream CPU-bound throughput well below shaper rate. **Verdict:** all
24 measurements pass with 0 retrans.

## Phase 6 v8 headline win — iperf-e canonical reproducer

The critical workload that motivated #1229 Phase 6:
`iperf3 -c 2001:559:8585:80::200 -P 12 -t 30 -p 5205` (16 G EXACT).

### Pre-v8 baseline (user's standing sample, master HEAD pre-PR #1230)

```
[ 5]:  733 Mbps    [ 7]:  730 Mbps    [ 9]: 1630 Mbps    [11]: 1570 Mbps
[13]:  863 Mbps    [15]: 3190 Mbps    [17]:  839 Mbps    [19]:  730 Mbps
[21]: 1560 Mbps    [23]: 1610 Mbps    [25]:  733 Mbps    [27]:  869 Mbps
[SUM]: 15.1 Gbps
```

Range: 730 – 3190 Mbps. Max/min ratio: **4.37×**. Per-flow CoV ≈
**60%**. Per-flow throughput is wildly uneven.

### Post-v8 (commit 7ac1b36f)

```
[ 5]: 1250 Mbps    [ 7]: 1030 Mbps    [ 9]: 1100 Mbps    [11]: 1030 Mbps
[13]: 1100 Mbps    [15]: 1030 Mbps    [17]: 1480 Mbps    [19]: 1230 Mbps
[21]: 1520 Mbps    [23]: 1230 Mbps    [25]: 1250 Mbps    [27]: 1100 Mbps
[SUM]: 14.3 Gbps
```

Range: 1030 – 1520 Mbps. Max/min ratio: **1.48×**. Per-flow CoV ≈
**13.3%** (computed: mean 1196, stddev 159).

### Headline numbers

| Metric | Pre-v8 | Post-v8 | Improvement |
|--------|--------|---------|-------------|
| Per-flow CoV | 60% | **13.3%** | **4.5× reduction** |
| Max/min ratio | 4.37× | **1.48×** | **3× tighter** |
| Min flow rate | 730 Mbps | **1030 Mbps** | **+41%** |
| Max flow rate | 3190 Mbps | 1520 Mbps | -52% (intentional) |
| Aggregate | 15.1 Gbps | 14.3 Gbps | -5% (within plan §v8 budget) |

The 5% aggregate drop is the lease-time vs send-time slip
documented in plan §v6.4 — bytes leased in epoch N TX in N+1 are
counted at lease time, so the rate cap is slightly more conservative.
The user accepted aggregate trade-offs in earlier project memory; the
flow-fairness win is the explicit objective.

## iperf-c saturated regression check

`iperf3 -P 12 -p 5203` (25G EXACT). Per-flow throughput at saturation
is dominated by sender-side TCP unfairness + inter-worker CPU
asymmetry per the recipe doc — observed_cov stays ~21% pre/post.

| Direction | Pre-v8 (recipe baseline) | Post-v8 | Delta |
|-----------|--------------------------|---------|-------|
| push | 22.7 Gbps | **19.3 Gbps** | **-15%** |
| reverse | ~22 Gbps | **22.1 Gbps** | flat |

**push direction shows ~15% aggregate regression.** This was anticipated
in plan §v8.10 open question 6: at 22.7G saturation, workers ARE
CPU-bound; per-worker fair share + grace period throttles fast workers
that can't fully share their unconsumed quota with peers who can't
consume more (because they're CPU-pegged). Reverse direction unaffected.

This is the trade-off the plan documented and the user accepted. If
the iperf-c push regression is unacceptable, the v8 mechanism would
need a follow-up to detect "all peers CPU-bound" and disable the
fair-share gate (effectively reverting to legacy greedy under that
condition). Out of scope for the current PR per §v8 out-of-scope list.

## Summary

| Workload | Result |
|----------|--------|
| Pass A (CoS off) | ✅ no regression, 22.5–22.9 Gbps reverse 12-stream |
| Pass B (24 per-class measurements) | ✅ all pass, 0 retrans |
| **iperf-e 12-stream (canonical)** | ✅ **CoV 60% → 13%, 4.5× reduction** |
| iperf-c push saturated | ⚠️ -15% aggregate (plan-documented trade-off) |
| iperf-c reverse saturated | ✅ flat |

Cluster smoke validates the v8 mechanism delivers exactly what the
plan predicted: dramatic per-flow fairness improvement on shaper-
bound multi-flow workloads (iperf-e style); modest aggregate cost
on saturated workloads where workers were already CPU-bound (iperf-c
push). The empirical iperf-e improvement is the largest dataplane
fairness win documented in the cross-worker fairness drive.
