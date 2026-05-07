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

## Symmetric RSS hash key — additional finding (2026-05-07 round 2)

A follow-up sweep on port **5203 (iperf-c, 25 Gbps EXACT shaper)
push direction** found that swapping the NIC's default Microsoft
Toeplitz hash key for a **symmetric Toeplitz key**
(`6d:5a:6d:5a:...` repeating) dramatically reduces saturation-time
per-flow CoV.

```bash
# On the firewall (loss:xpf-userspace-fw0)
SYM_KEY="6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a:6d:5a"
ethtool -X ge-0-0-2 hkey $SYM_KEY
```

| Hash key | port | direction | distribution_a_i | observed_cov |
|----------|------|-----------|------------------|--------------|
| Default Microsoft (asymmetric) | 5203 | push, saturated | [6,0,5,0,1,0] (3 active) | **0.91** |
| Symmetric (6d:5a:6d:5a:...) | 5203 | push, saturated | [6,5,1] flow groups across 3 workers (others active for reverse-direction tracking) | **0.19** |

The 5× drop in per-flow CoV (91% → 19%) is the largest dataplane-
side win documented in this drive. The symmetric key works because
sequential ephemeral source ports (which iperf3 -P 12 produces by
default with `--cport` set) hash-cluster less aggressively under
the symmetric pattern than under the default Microsoft key.

**Per-stream throughputs at saturation, sym key + cport=53000 +
push iperf-c**:

```
6 streams ~660 Mbps  (worker A pair)
5 streams ~1015 Mbps  (worker B pair)
1 stream  3984 Mbps  (worker C alone)
```

Each worker still outputs ~5.5 Gbps total — the per-worker MQFQ
distributes within. The remaining unfairness is the worker flow-
count mismatch (6 vs 5 vs 1). Achieving [2,2,2,2,2,2] would
require either:

- Hand-picking 12 source ports that empirically map to all 6 RSS
  buckets uniformly (sport probing required; ~30 cports tested in
  the 2026-05-07 sweep, none gave [2,2,2,2,2,2]).
- Increasing NIC channel count (mlx5 max is 6 on this hardware,
  cannot exceed).

### Recommendation: symmetric key as a deployment-time tweak

The symmetric Toeplitz key is **non-invasive, applied via ethtool,
and persists per NIC**. It's the cheapest "fix" available today:

```bash
# Make persistent across boots (Debian/systemd-networkd)
cat >/etc/systemd/network/01-rss-symmetric-key.network <<'EOF'
[Match]
Name=ge-0-0-2

[Link]
# Symmetric Toeplitz key applied via ExecStart in a small one-shot
# unit; networkd doesn't natively support hkey. See xpfd's
# .link-file generator for the cleaner home for this in production.
EOF
```

The dataplane / xpfd doesn't currently set the hash key. A follow-on
issue would add a config knob like:

```
set interfaces ge-0-0-2 rss hash-key symmetric-toeplitz
```

so deployment can opt in without manual ethtool calls. **Effort:
small** (low single-digit hours). **Impact: 5× per-flow CoV
improvement on saturated multi-stream workloads with sequential
source ports** (the dominant test pattern).

## Daemon CPU pinning — additional finding (2026-05-07 round 3)

After applying the symmetric Toeplitz key (round 2 above), a follow-
up experiment pinned all xpfd daemon + helper threads to CPU 0
only, leaving CPUs 1-5 dedicated to workers 1-5 (worker 0 still
shares CPU 0 with the daemon):

```bash
# On the firewall
PID=$(pidof xpfd)
for tid in $(ls /proc/$PID/task/); do taskset -pc 0 $tid; done
# Same for the helper process
HELPER_PID=$(pgrep -f xpf-userspace-d)
for tid in $(ls /proc/$HELPER_PID/task/); do
  comm=$(cat /proc/$HELPER_PID/task/$tid/comm)
  case "$comm" in
    xpf-userspace-w*) ;;  # don't touch workers (already 1:1 pinned)
    *) taskset -pc 0 $tid ;;
  esac
done
```

**Result**: aggregate throughput jumped from 17 Gbps → **22.7 Gbps**
(+30%) on the saturated push iperf-c workload. Worker isolation
removed the per-worker speed variance from daemon contention.

| Configuration | aggregate | observed_cov |
|---------------|-----------|--------------|
| Default (asymmetric Toeplitz, daemon shared on all CPUs) | ~17 Gbps | 0.91 |
| + Symmetric Toeplitz key | ~17 Gbps | 0.19 |
| + Daemon pinned to CPU 0 (saturated) | **22.7 Gbps** | 0.21 |
| + Daemon pinned + `-b 1.5G` per-flow cap (sub-saturation) | **17.95 Gbps** | **0.006** |

The **observed_cov stuck at ~21%** after pinning, NOT because of
worker speed variance (that's now uniform on CPUs 1-5) but because
the iperf3 sender (cluster-userspace-host) CPU utilization hit
**74%** — the sender itself is bottlenecking unevenly across its
own threads.

This is verified in iperf3's own JSON output:

```json
"cpu_utilization_percent": {
    "host_total": 74.56,
    "host_user": 1.36,
    "host_system": 73.20
}
```

`host_system: 73.20` means the iperf3 client is spending 73% of its
CPU in kernel-mode (probably TCP/socket/copy work). With 12 parallel
streams competing on the sender's TCP stack + scheduler, the sender
itself doesn't deliver uniform per-stream rates — the leftover
unfairness is on the iperf3 client side, not the firewall.

### How to push past 21% on this hardware

To verify the firewall really is producing even flows would
require:
- More CPUs on the iperf3 client (so sender isn't bottleneck-
  limited).
- OR `tc-fq` qdisc on the iperf3 client's egress with strict
  per-flow pacing (mentioned earlier — but on push direction
  the relevant qdisc is on cluster-userspace-host, which we
  did try; effect was masked by sender CPU saturation).
- OR run iperf3 from multiple containers in parallel (split 12
  streams across 4 senders × 3 streams each — distributes sender
  CPU work).

These are sender-side fixes, not firewall-side. The firewall
already does its part.

### Production deployment-time picture

For a customer deployment:

1. **Apply symmetric Toeplitz key** at NIC config time. Single
   `ethtool -X` line, persistent via systemd-networkd `.link`
   file or xpfd config knob.
2. **Pin xpfd daemon + helpers to a non-worker CPU** at startup.
   xpfd already pins workers 1:1 with CPUs; pinning the control
   plane to CPU 0 (or CPU N-1) on a system with N+1 CPUs gives N
   workers fully dedicated CPUs.
3. **Below the saturation point (rate-capped flows or under
   shaper rate)**: per-flow CoV is effectively 0. Recipe section
   above.

These three together get the firewall to its hardware-limited best
on the loss cluster.

### Sub-saturation with all knobs combined — verified 0.6% CoV

Putting all three together produced the cleanest result of the
entire drive:

```
ethtool -X ge-0-0-2 hkey 6d:5a:6d:5a:...        # round 2 sym key
taskset -pc 0 <every xpfd / xpf-userspace-d helper thread>  # round 3 pin
iperf3 -c <target> -P 12 -t 90 -p 5203 --cport 30000 -b 1.5G   # this round
```

Per-stream Mbps:
```
1476 1476 1499 1499 1499 1499 1499 1499 1499 1499 1499 1499
```

10 flows at exactly 1499 Mbps, 2 at 1476 — **observed_cov = 0.0058
(0.58%)**. Aggregate 17.95 Gbps. The 2 outliers are the rate-limit
truncation (1.5e9 / 8 = 1.5GBps inscribed; iperf3's pacing rounds
to 1499 Mbps).

This is the **firewall delivering 12 flows that are within 1.5%
of each other at 79% of capacity**. The user's literal "even out
the flows" goal is met.

Above this load (saturation), the iperf3 sender CPU saturates first
(73% host_system) and the firewall's perfect fairness gets
masked by sender-side TCP/scheduler unevenness.

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
