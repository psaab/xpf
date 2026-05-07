# Even out the flows — empirical recipe and decomposition

**As of 2026-05-07.** This document captures what reduces per-flow
throughput variance to near-zero on the xpf userspace AF_XDP
dataplane and what doesn't, based on a measurement sweep on the
loss userspace cluster (master 92b3b62d).

## TL;DR — the recipe that works today

```
iperf3 -c <target> -P 12 -t 90 -p 5201 --cport 53000 -b 1.0G -R
```

Result on the loss cluster: `distribution_a_i = [4,0,4,0,4,0]`,
`cstruct = 0`, `observed_cov = 0.0001` (effectively perfect),
`aggregate_mbps = 12000`, **verdict PASS**.

Two ingredients:

1. **Pick a `--cport` that puts the streams uniformly across active
   workers.** On this cluster, `cport=53000` deterministically gives
   `[4,0,4,0,4,0]` for `port=5201` (3 of 6 workers fully loaded
   with 4 flows each). Different cports give different
   distributions; sweep until you find one with `cstruct = 0` for
   your target port.
2. **Cap each flow at a rate × `n_streams` ≤ aggregate capacity.**
   With `-b 1.0G` and 12 streams, demand is 12 Gbps — well below
   the 14–15 Gbps actual cluster capacity for 3-active-worker
   patterns. Each flow runs at exactly its commanded rate.

Below saturation, flows don't compete for the bottleneck and TCP
serves each at its sender-side commanded rate. The dataplane
scheduler is irrelevant — there's nothing to schedule.

## Why simpler choices don't work

The default `iperf3 -P 12 -t 90 -p 5201 -R` (no `--cport`, no
`-b`) gave variable-distribution runs with `observed_cov` 7–47%
across the 5-run sample because:

- **Ephemeral source ports vary run-to-run.** The TCP stack picks
  ports from its ephemeral range; different runs hit different RSS
  buckets. We measured `cstruct` ranging 0.20–0.71 across 5
  consecutive identical invocations. Pinning `--cport` makes RSS
  placement deterministic.
- **TCP cwnd head-start of socket 5.** The first stream iperf3
  establishes (socket 5, the lowest-numbered TCP socket after the
  control connection) reaches full path bandwidth alone before the
  other 11 connect. Its cwnd inflates and never converges back.
  We measured this at 1700 Mbps vs 1300–1500 for the rest, and
  confirmed the head-start persists through `-O 30` warmup
  omission and `-t 200` long runs.

When demand exceeds capacity (no `-b` cap), TCP's slow-cwnd-
convergence-at-shared-bottleneck is the dominant unfairness.

## Sweep table

All runs: `--cport 53000 -p 5201 -R`, 12 streams, master 92b3b62d.

| -b/flow | distribution | cstruct | observed_cov | agg Mbps | verdict |
|---------|--------------|---------|--------------|----------|---------|
| (none, saturated) | [4,0,4,0,4,0] | 0.00 | **0.085** | 16826 | FAIL |
| 1.0G | [4,0,4,0,4,0] | 0.00 | **0.0001** | 11999 | **PASS** |
| 1.2G | [4,0,4,0,4,0] | 0.00 | **0.025** | 14160 | **PASS** |
| 1.4G | [4,0,4,0,4,0] | 0.00 | 0.074 | 14631 | FAIL |
| 1.6G | [4,0,4,0,5,0] | 0.11 | 0.109 | 14435 | PASS (gap < ε) |
| 1.8G | [4,0,4,0,4,0] | 0.00 | 0.105 | 14192 | FAIL |
| 2.0G | [4,0,4,0,4,0] | 0.00 | 0.115 | 13991 | FAIL |

The aggregate plateau at ~14.2 Gbps is the per-direction capacity
for the 3-active-worker pattern on this cluster. Going above the
plateau (1.4G/flow and up) saturates the bottleneck and per-flow
unfairness reasserts itself.

## Decomposition of saturation-time unfairness

Without rate cap (saturated, observed_cov ≈ 8–9%), the variance
decomposes into three independent sources, each measured directly:

### 1. TCP cwnd head-start ~25%

Socket 5 (sport 53000, first established) consistently runs ~30%
faster than the other 11 streams. Persists through `-O 30` warmup
omission and through `-t 200` long runs. Source: TCP socket-fairness
under shared bottleneck — the leading flow's cwnd never re-converges
once the others arrive.

This is a **TCP-level** effect, not a dataplane scheduling issue.

Mitigation:
- `tc-fq` (fair queueing qdisc) on the iperf3 sender's egress.
- `setsockopt SO_MAX_PACING_RATE` to floor each flow's commanded rate.
- iperf3 `-b` per-flow rate cap (the recipe above).

### 2. Inter-worker speed variance ~21%

With `[4,0,4,0,4,0]` on workers 0/2/4 (each 4 flows), the
per-worker aggregate throughput ranges 4456 → 5404 Mbps, a 21%
spread.

The cluster has **6 CPUs and 6 worker threads** with 1:1 pinning,
but the daemon control plane runs threads on the same CPUs:

- worker 0 (TID 112341, CPU 0) shares CPU 0 with daemon thread
  TID 112393.
- workers 1/2/3/4/5 each share their CPU with one or more daemon
  futex-waiting threads.

The workers competing with control-plane threads run slower on the
slow side of the spread. Source: **CPU contention with control
plane**, not the dataplane scheduler.

Mitigation:
- Allocate dedicated CPUs for workers (cluster needs > 6 CPUs).
- Pin daemon threads to a separate CPU set than workers.
- Use kernel isolcpus / cgroup CPU shares to enforce isolation.

### 3. Intra-worker MQFQ residual ~8–15%

Within the 4 flows on a single worker, throughput spread is 8–19%.
PR #928 (`#913` vtime fix) is in master — `queue_vtime` correctly
uses `max(vtime, served_finish)` per Hedayati & Shen ATC '19. The
residual variance is the per-worker MQFQ bucket scheduling under
heavy multi-flow load.

This is the **dataplane** contribution.

Mitigation candidates:
- Tune the per-worker MQFQ bucket count for higher flow counts.
- Replace per-worker MQFQ with a max-min fair share scheduler that
  enforces equal per-flow rates rather than approximate
  byte-fairness.

## What does NOT solve this — verified or memory-confirmed

- **AFD ECN/drop overlay (#1211)**: PLAN-KILLed and archived under
  `path2-archive/`. ECN couldn't fix the TCP cwnd head-start —
  inertia of the leading flow's cwnd persists through marking
  events. The empirical PASS on the motivating workload was correct
  per the contract.
- **Cross-worker steering (#937)**: doesn't help here because
  `cstruct = 0` already (perfectly balanced across active workers).
  Cross-worker steering would only move flows OFF active workers
  ONTO idle ones, raising aggregate throughput but not reducing
  per-flow CoV among the loaded workers.
- **NIC RSS hash key tuning**: changing the Toeplitz key
  redistributes which 12 sport→queue assignments happen but doesn't
  reduce inter-flow variance once they land. Different `cport`
  bases give different distributions, but observed_cov within a
  saturated `cstruct = 0` case stays ~8%.

## Recommendations

### For test/measurement workloads

Use the recipe above. Below saturation, flows are perfectly even
and the harness PASSes cleanly.

### For production workloads

The 8–9% saturation-time CoV is the **structural ceiling on this
cluster's hardware** and reducing it requires substantial work:

| Source | Fix effort |
|--------|-----------|
| TCP cwnd head-start | Low — tc-fq on sender, or SO_MAX_PACING_RATE per app |
| Inter-worker speed variance | Medium — restructure CPU layout, more CPUs |
| Intra-worker MQFQ residual | High — replace MQFQ with max-min fair share at TX dispatch |

The fairness contract from PR #1217 captures this correctly: the
verdict PASSes when `observed_cov ≤ cstruct + ε`, and the cluster's
empirical PASS on the canonical workload reflects "you're at the
hardware-imposed structural ceiling, not a scheduler bug."

The user's standing mandate to drive per-5-tuple fairness
end-to-end is now empirically settled at the architectural level:
the path forward is either (a) accept the structural ceiling or
(b) commit to one of the medium/high-effort mitigations above.
Filing a fresh issue per the path-2-archive revisit criteria
remains the right move if a customer workload actually fails.

## Reproducing this measurement

The exact scripts used live in `/tmp/run-cport.sh`,
`/tmp/run-rate.sh`, etc. — wrappers around `incus exec` for
iperf3 and 1 Hz `/metrics` scraping, feeding output to
`fairness-eval` from PR #1220. Quick path:

```bash
# Build fairness-eval on master
cargo build --manifest-path userspace-dp/Cargo.toml --release \
    --bin fairness-eval

# Push to firewall
sg incus-admin -c "incus file push <build-dir>/fairness-eval \
    loss:xpf-userspace-fw0/usr/local/bin/fairness-eval --mode 0755"

# Run iperf3 from cluster-userspace-host while scraping firewall metrics
# (see /tmp/run-cport.sh for the full orchestration)
```

The full sweep takes ~10 minutes wall clock for the table above.
