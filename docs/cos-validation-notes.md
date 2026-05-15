# CoS admission validation — methodology and current baseline

This file documents how to validate changes to the userspace-dp CoS admission path
(anything that touches `cos_flow_aware_buffer_limit`,
`cos_queue_flow_share_limit`, `apply_cos_admission_ecn_policy`, or the
admission block in `enqueue_cos_item`). Read it before opening a PR that
claims to move TCP fairness, retransmit count, or cwnd-collapse numbers on
the 16-flow iperf3 workload — otherwise you are likely to repeat the
mistake described in #725 or the VLAN-offset bug resolved in #728.

## How to read admission drop counters live

Since #724, `show class-of-service interface` renders three per-queue
counters on an indented `Drops:` line:

```
Queue  Owner  Class    ...  Buffer     Queued pkts  Queued bytes  ...
4      1      iperf-a  ...  1.19 MiB   299          443.24 KiB    ...
       Drops: flow_share=1923  buffer=0  ecn_marked=0
```

Definitions (from `CoSQueueDropCounters` in `userspace-dp/src/afxdp/types.rs`):

- `flow_share` — packets dropped because a single flow's bucket already holds
  its entire `share_cap` worth of bytes. The dominant failure mode on
  flow-fair exact queues under multi-flow load **before** ECN marking
  landed end-to-end.
- `buffer` — packets dropped because aggregate queue depth exceeded
  `buffer_limit`. Usually zero because #716 + #720 keep the aggregate
  nowhere near the cap.
- `ecn_marked` — count of successful ECN CE marks. Zero when either
  (a) the threshold never trips, or (b) no ECT packets reach the
  firewall, or (c) the marker is reading the wrong byte (see #728 —
  the VLAN-offset bug made the marker dormant even with ECT(0)
  on the wire).

Zero-valued counters are still printed. That is deliberate: an operator
needs to see the zero to confirm the counter is wired and the drop path
simply is not firing, versus the telemetry being broken.

The CLI joins configured CoS interfaces to live userspace runtime rows by
configured name first, then by the binding egress ifindex. Reverse egress
configs can display as a physical unit such as `ge-0-0-1.0` while the runtime
snapshot carries a different alias for the same ifindex; the ifindex fallback
keeps those reverse-path counters visible instead of reporting
`Runtime: unavailable`.

`show chassis cluster data-plane userspace` also prints an aggregate CoS
admission attribution beside the generic `TX errors` counter:

```
TX errors:                 332019
TX errors non-admission:   50
CoS queue drops lifetime:  331969
CoS admission drops:       331969
CoS flow-share drops:      111471
CoS buffer drops:          220498
CoS ECN marked:            16496600
TX shared recycle unk:     0
```

`TX errors` remains the generic superset used by the dataplane's error
paths. CoS admission drops intentionally still increment it because a packet
was not transmitted, but the adjacent `TX errors non-admission` line subtracts
the binding-scoped `CoS queue drops lifetime` counter from the binding-scoped
`TX errors` counter so AF_XDP/ring/shared-UMEM failures are not confused with
expected shaper backpressure. Those two counters share the same lifetime and
survive CoS config resets. The binding-scoped CoS subset includes admission
rejects and reset-time CoS queue drains.

The formatter deliberately does not subtract the current-runtime
`CoS admission drops` reason split from `TX errors`; those reason counters live
on the active CoS runtime and reset on CoS config commits. If the
binding-scoped CoS subset briefly appears larger than `TX errors` during a
publication window, the formatter clamps `TX errors non-admission` to zero.
Treat that as sample skew unless it persists across later snapshots.

The summary `CoS admission drops`, `CoS flow-share drops`, `CoS buffer drops`,
and `CoS ECN marked` lines are aggregate sums across the current CoS runtime's
interfaces and queues. They are useful for explaining the active scheduler
epoch, but they can reset after a CoS config commit. If `CoS queue drops
lifetime` is larger than the current reason split, a prior epoch or reset-time
queue drain likely contributed. Treat non-zero lifetime CoS queue drops as a
shaping or buffering question first; treat non-zero non-admission TX errors as
the higher-severity transmit-path question.

### Reading them during an iperf3 run

```bash
# 16-flow iperf3 in background
incus exec loss:cluster-userspace-host -- \
  iperf3 -c 172.16.80.200 -P 16 -t 30 -p 5201 -i 0 >/dev/null 2>&1 &

sleep 10   # let the queue fill and the counters move

# Read the live counters mid-test
incus exec loss:xpf-userspace-fw0 -- \
  /usr/local/sbin/cli -c "show class-of-service interface"

wait   # let iperf3 finish
```

The counters are monotonic from process start. For a delta over a run,
snapshot before and after and subtract.

## gRPC server-side capture

AF_XDP bypasses the kernel network stack, so `tcpdump` on the firewall
netdev (`reth0`, `reth0.80`, physical member `ge-0-0-0`) **does not see
bulk data-plane traffic** — it only sees slow-path packets that fell back
through the kernel. This makes firewall-side netdev captures useless for
confirming what reached or left the dataplane on the hot path.

The `iperf-grpc-tcpdump` skill in `.codex/skills/iperf-grpc-tcpdump/SKILL.md`
solves this by running `tcpdump` on the iperf3 **server** over a gRPC
capture endpoint at `172.16.80.200:50051`, synchronised with LAN/WAN
captures on the active firewall and an iperf3 run from the client.

Ad-hoc capture (no iperf3 coordination) looks like:

```bash
grpcurl -plaintext -d '{"iface":"eth0","duration_s":30,"filter":"tcp port 5201"}' \
  172.16.80.200:50051 capture.CaptureService/Run > server-grpc.txt
```

For the full orchestrated run (server + LAN + WAN + iperf3 + stats
before/after), use the skill's helper:

```bash
.codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh --family 4 --parallel 16 --duration 30
```

This capture path is how #728 was diagnosed: server-side tcpdump
confirmed ECT(0) bits were present on ingress frames **before** the
firewall's marker ran, which ruled out "the endpoint doesn't negotiate
ECN" and pointed directly at the marker's L3 offset. Without the gRPC
capture we would have spent another round chasing phantom endpoint
problems. Use it whenever a local tcpdump shows `tos 0x0` on a VLAN
subinterface before concluding "ECN isn't negotiating" — the real packet
on the wire may say otherwise.

## Choosing a fix path

When the counters show something different from the current baseline
(see below), the pathology and the right fix may be different. Before
pulling a row out of the table below, **check per-queue cap
utilisation first**: pull the queue's configured `transmit_rate_bytes`
from `show class-of-service interface`, divide the measured 16-flow
aggregate by it, and only attribute residual fairness jitter to TCP
physics (per-flow ratio ≥ ~1.2×, retrans non-zero, rate ratio > 1.2×)
*after* confirming the queue is delivering ≥ 95 % of its cap. If the
queue is under-delivering, the residual is scheduler misbehaviour
masquerading as TCP jitter — pre-#754 the 1 Gbps queue sat at 60 %
of cap and the jitter signal was an artefact of the ECN threshold
firing on every cwnd-growth attempt (see the "1 Gbps queue over-
throttle fix (post-#754)" section below).

The decision tree:

| `flow_share` | `buffer` | `ecn_marked` | Interpretation | Likely fix |
|---|---|---|---|---|
| low (~10s/flow/30s) | 0 | high (~100k/30s) | Current post-#728 baseline. ECN holds cwnd at the knee; residual drops are microburst arrivals the marker couldn't catch in time. **Verify queue delivers ≥ 95 % of cap before concluding "residual is TCP physics" — if cap utilisation < 95 %, the mark rate is the bug (see #754).** | #709 owner-worker hotspot / #718 Option B CoDel for the microburst residual. |
| high | low | 0 | Per-flow cap too tight; no ECN to soften it. Before concluding "endpoint doesn't negotiate ECN", run a gRPC server-side capture (see above) — #728 was this symptom caused by a VLAN-offset bug, not by the endpoint. | Confirm ECT on the wire via gRPC capture, then: fix marker if ECT present; otherwise ECN end-to-end, or CoDel (non-ECN AQM), or relax per-flow cap. |
| high | low | high | ECN fires but TCP still drops — ECN signal not enough | Lower ECN threshold, or combine with rate-based pacing |
| low | high | any | Aggregate cap tripping — bufferbloat | Revisit #720 clamp; look at operator `buffer-size` setting |
| 0 | 0 | 0 | Nothing is dropping; problem is elsewhere | Look at #709 (owner worker), #712 (CPU pinning), or network-layer loss |

#1312 pinned the canonical iperf fixture buffers for the low-rate exact
classes after reverse `-P 12` reproduced high retransmits with equal-flow
disabled: `scheduler-be` uses `buffer-size 500k` and
`scheduler-iperf-a` uses `buffer-size 4m`.

When `buffer-size` is omitted, queue `base` comes from
`max(transmit_rate_bytes/100, 96_000)` (10 ms of bytes with a 96 KB
floor), then `cos_flow_aware_buffer_limit` applies flow-aware expansion
and the #717 5 ms envelope clamp:
`base.max(prospective_active * 24 KB).min(delay_cap.max(base))`, where
`delay_cap = transmit_rate_bytes * 5 ms`.

These fixture overrides intentionally sit above that implicit cap because
the exact flow-fair admission gates need enough aggregate and per-flow
headroom to avoid persistent tail-drop at 12 active TCP flows. They also
trade latency headroom for retransmit suppression (`500k` at 100M ≈ 40 ms
residence; `4m` at 1G ≈ 32 ms at full queue). Treat changes to these
fixture values as admission-policy changes and rerun the q0/q4 reverse
sweep before trusting low-rate fairness evidence.
## Current dominant failure mode on this workload

**Observed 2026-04-17, post-#728.** This is a dated snapshot, not
timeless methodology. Re-measure before citing these numbers in a new PR.

Fixture: `test/incus/cos-iperf-config.set`, 1 Gbps exact queue on queue 4,
16-flow iperf3, `net.ipv4.tcp_ecn=1` end-to-end, 30-second runs.

| Counter | Value |
|---|---|
| Rate ratio (max/min across flows) | 1.28× |
| Retransmits / 30 s | ~114 k |
| `flow_share_drops` / 30 s | ~75 (≈12 per flow) |
| `buffer_drops` / 30 s | 0 |
| `ecn_marked` / 30 s | ~97,349 |
| cwnd steady state | 8–17 KB |
| Queue depth steady state | ~150 KB (≈1.5 ms queueing latency) |

The admission path is doing what it was designed to do: ECN holds every
flow at the fairness knee (cwnd ≈ 12 KB), aggregate queueing stays around
1.5 ms, and packet drops are rare.

The residual ~12 `flow_share` drops per flow per 30 s are not the
RTO-driven collapse #704 was about — they come from microburst arrivals
where several packets from the same flow land in the same enqueue tick
faster than CE marks can propagate back through the TCP ack clock. The
remaining levers for this residual are the ones already tracked:

- **#709 (owner-worker hotspot)** — pinning the admission path to a
  dedicated worker reduces enqueue-tick variance, which reduces the
  microburst window.
- **#718 Option B (CoDel)** — adds a second AQM dimension that reacts
  to sojourn time, catching bursts that ECN threshold-based marking
  misses.

Neither is structurally required. The current baseline is a healthy,
fair, ECN-paced queue; the residual is the tail of what AQM can do
without rate pacing on the sender.

## History: the "ECN never negotiated" fire drill

**Resolved 2026-04-17 via #728 (VLAN-aware L3 offset).**

An earlier version of this doc documented a "limitation" that the
iperf3 server at `172.16.80.200` did not negotiate ECN, leaving
`ecn_marked=0` regardless of client/firewall `tcp_ecn` settings. That
was wrong. The server negotiates ECN correctly and ECT(0) packets were
reaching the firewall. The real bug was a hard-coded `TX_L3_OFFSET = 14`
in both Local and Prepared markers; on a VLAN subinterface
(`reth0 unit 80`) the frame carries an 802.1Q tag and L3 lives at
offset 18. The marker was reading the VLAN TCI byte, which rarely
matches ECT(0)/ECT(1), so the RFC 3168 NOT-ECT early-return fired on
every packet.

The lesson: **do not conclude "ECN isn't negotiated" from a
firewall-side tcpdump that shows `tos 0x0`**. AF_XDP means the
firewall-side capture doesn't see dataplane traffic at all, and even a
local client-side capture can be misleading if the path crosses a VLAN
boundary. Use the gRPC server-side capture at `172.16.80.200:50051` to
disambiguate where in the chain the ECT bits are being lost (or
mis-read).

The verification command still works — the conclusion to draw from it
is narrower than before:

```bash
# Capture 4 packets from an in-progress iperf3 run and look at tos.
# tos 0x0 in both directions does NOT by itself mean ECN is not
# negotiating — it may mean you are reading the wrong interface or
# hitting the #728 class of bug. Cross-check with a server-side gRPC
# capture before committing to that conclusion.
incus exec <client> -- tcpdump -v -c 4 -n 'tcp port 5201'
```

## Reading the owner-profile counters

Since #709 (Option E), `show class-of-service interface` renders a
second indented line under each queue row whose owner is a single
worker. This gives operators a latency view of the owner-worker
drain path without having to scrape Prometheus or attach perf:

```
Queue  Owner  Class    ...  Buffer     Queued pkts  Queued bytes  ...
4      1      iperf-a  ...  1.19 MiB   299          443.24 KiB    ...
       Drops: flow_share=75  buffer=0  ecn_marked=97349
       OwnerProfile: drain_p50=1us  drain_p99=16us  redirect_p99=2us  owner_pps=12345  peer_pps=6789
```

Field meanings (from `BindingLiveState` in `userspace-dp/src/afxdp/umem.rs`):

- `drain_p50 / drain_p99` — p50/p99 of the time spent inside
  `drain_shaped_tx` across its servicing tick. Sampled on EVERY
  invocation, bucketed into power-of-two ns buckets from 1 µs to
  ~16 ms. Lower bound of the bucket containing the Nth percentile
  sample is reported — it is a ballpark, not an exact stat.
- `redirect_p99` — p99 of the time spent in
  `BindingLiveState::enqueue_tx_owned` (the redirect-inbox push path
  peer workers use to deliver packets to the owner). Sampled 1-in-256
  on each producer to keep the common case allocation- and
  timer-free.
- `owner_pps` — packets the owner sourced itself on the window
  (accumulator, cleared by
  `clear statistics class-of-service`).
- `peer_pps` — packets peer workers redirected into the owner's
  MPSC inbox on the same window. Ratio tells the operator whether
  the owner is sourcing the bulk of the work itself or acting
  mostly as a fan-in point for peer redirects.

### What the shape means for #709

The plan (`docs/pr/709-owner-hotspot/plan.md` §3) lays out a decision
tree that converts these counters into a fix path:

- **drain_p99 ≈ drain_p50 (flat right tail).** The owner drain is
  not the bottleneck. Close #709 as not-needed; keep #712 for CPU
  jitter.
- **drain_p99 ≥ 10× drain_p50 (fat right tail).** The owner has a
  head-of-line stall — most drains finish fast but a long tail of
  slow ones accumulates. Data supports Option B (work-stealing
  off-owner drain). The structural fix is worth the complexity.
- **drain_p99 is fine but redirect_p99 > 1 ms.** Unusual post-#715
  (the MPSC inbox is lock-free); if seen, pivot to a smaller
  producer-side fix rather than Option B.
- **drain_p99 ~ µs but owner_pps >> peer_pps.** The owner is
  overloaded with its own RX/forward/NAT work and only does a small
  amount of cross-worker redirect drain — Option C (RSS retargeting)
  or Option D (owner rotation) becomes more justified because the
  issue is "owner doing 2× work" not "inbox latency".

The guideline is the same one `engineering-style.md` sets out for
all perf PRs: read the counters, then decide. Iterating on fixes
without reading them is how we ship dormant code.

### Operational gotchas

- **Non-exact / shared_exact queues have NO OwnerProfile line.**
  The telemetry is per-binding on the owner's `BindingLiveState`;
  if there is no single owner binding (shared_exact at ≥ 2.5 Gbps,
  or non-exact queues), the CLI suppresses the row. An operator
  wanting the same view for a high-rate shared queue must wait for
  a sharded-per-worker histogram to land (not planned).
- **The counters are process-monotonic.** For a windowed delta on
  live traffic, snapshot before and after and subtract — same as
  the `Drops:` line.
- **Prometheus:** the same data flows out as
  `xpf_cos_drain_latency_ns_bucket{ifindex, queue_id, bucket_hi_ns}`,
  `xpf_cos_redirect_acquire_ns_bucket{...}`,
  `xpf_cos_drain_invocations_total{ifindex, queue_id}`,
  `xpf_cos_owner_pps{ifindex, queue_id}`, and `xpf_cos_peer_pps{...}`.
  Expected cardinality per the plan: ≤ 8192 series per histogram.

## CPU pinning layout for the loss lab

**Measured 2026-04-17 for #712 Option A.** Conclusion: the
`CPUAffinity=` directive on `xpfd.service` is a no-op on the 6-core
loss userspace lab because `userspace-dp` re-pins its workers inside
the process after systemd's mask is applied. Keep this section dated;
re-measure if any of the three blockers below move.

### Intended layout on the 6-core lab

The host is a 6-CPU VM. NIC IRQ distribution on fw0 under 16-flow
iperf3 load, sampled from `/proc/interrupts`:

- mlx5_comp0 (WAN VF RX q0) → CPU 0, ~800 M interrupts
- mlx5_comp1 (WAN VF RX q1) → CPU 1, ~900 M interrupts
- mlx5_comp2..5 (WAN VF RX q2..5) → CPUs 2..5, ~500-900 M each
- virtio-input/output q0..5 → pinned 1-per-CPU across CPUs 0..5

Each CPU carries NIC IRQ load; CPUs 0-1 are the hottest. The recipe in
`docs/712-cpu-pinning-recipe.md` §"6-core host" reserves CPUs 0-1 for
IRQ + housekeeping and gives xpfd and its four dp workers CPUs 2-5:

```
[Service]
CPUAffinity=2 3 4 5
```

### Why that recipe is a no-op today

`xpf-userspace-dp` calls `pin_current_thread(worker_id)` in
`userspace-dp/src/afxdp/neighbor.rs`, which issues
`sched_setaffinity(0, CPU_SET(worker_id % nproc))` per worker **after**
systemd has installed the unit mask. `nproc` (via
`std::thread::available_parallelism()`) correctly reports 4 when the
process is launched with `CPUAffinity=2 3 4 5`, but the call pins each
worker to absolute CPU `worker_id % 4` — i.e. CPU 0, 1, 2, 3 — not to
the 0th..3rd CPU of the allowed set. Result: the four hot-path workers
land on CPUs 0-3 regardless, colliding with `mlx5_comp0` and
`mlx5_comp1`. The Go main and the dp aux threads (state-writer,
event-stream, slowpath, neigh-monitor) do honour the mask and run on
CPUs 2-5.

### Measurement

16-flow iperf3 × 30 s × 3 runs, client
`cluster-userspace-host`, target `172.16.80.200`, CoS fixture
`test/incus/cos-iperf-config.set` applied, fw0 primary. Computed with
`/tmp/712-pinning/analyze.py` (iperf3 `-J` on the client; per-flow CoV
is the standard deviation of the per-second bps samples on each stream,
divided by that stream's mean).

| Metric | Pre-pin mean | Post-pin mean | Δ |
|---|---|---|---|
| Rate ratio (max/min per-flow) | 1.39× | 1.45× | +4% (worse) |
| Retransmits / 30 s | 181 k | 204 k | +13% (worse) |
| Per-flow CoV mean | 14.3% | 15.9% | +1.6 pp (worse) |
| Per-flow CoV max | 25.4% | 26.4% | +1.0 pp (flat) |

All deltas within run-to-run noise. No metric moved in a good
direction. Acceptance criterion from #712 — per-flow stdev/mean ≤ 10% —
was not met pre-pin (~14%) and not closer post-pin. Per
`engineering-style.md` §"Hot-path coding discipline", the directive
was reverted in the same PR; the recipe doc lives on as design intent.

### Blockers before Option A can land as a win

1. ~~`pin_current_thread` must pick the Nth allowed CPU, not absolute
   CPU N.~~ **Fixed in #740.** Workers correctly honour the inherited
   mask as of master `b5e7fc2f`. Verified during the #741 retry below.
2. Option B (kernel cmdline `isolcpus=`+`nohz_full=`) would remove
   kernel timers and RCU callbacks from worker CPUs entirely. It
   requires a cmdline edit and reboot, so deployment shape has to opt
   in. Tracked as a follow-up to #712 (#739). After the #741 retry
   this is the next lever to try on this hardware.
3. Option D (cgroup cpuset) is softer and does not require a cmdline
   change but needs operator decisions about which cpuset holds which
   non-xpfd process. Tracked as a follow-up to #712.

## CPU pinning retry post-#740

**Measured 2026-04-17 for #712 Option A retry (#741).** Conclusion:
with the #740 fix in place, workers correctly pin to CPUs 2-5 — but
the aggregate iperf3 metrics still do not move by the #712 thresholds
on this hardware. The layout is verified as applied; the 6-core lab
does not benefit from systemd-level pinning alone.

### Verification (Phase 3)

Taken live with `CPUAffinity=2 3 4 5` loaded, xpfd running, before
the Phase 4 iperf3 runs:

```
pid 65616's current affinity mask: 3c

65619 ctrl-c         cpus_allowed=2-5 psr=3
65620 iou-wrk-...    cpus_allowed=2-5 psr=5
65628 neigh-monitor  cpus_allowed=2-5 psr=2
65621 session-socket cpus_allowed=2-5 psr=2
65618 xpf-event-strea cpus_allowed=2-5 psr=2
65622 xpf-slowpath   cpus_allowed=2-5 psr=3
65617 xpf-state-write cpus_allowed=2-5 psr=4
65616 xpf-userspace-d cpus_allowed=2-5 psr=5
65624 xpf-userspace-w cpus_allowed=2   psr=2
65625 xpf-userspace-w cpus_allowed=3   psr=3
65626 xpf-userspace-w cpus_allowed=4   psr=4
65627 xpf-userspace-w cpus_allowed=5   psr=5
```

Every worker on its own CPU in {2,3,4,5}; `psr` matches
`cpus_allowed` one-to-one. No worker lands on CPU 0 or 1. The
pre-#740 failure mode — workers on CPUs 0-3 regardless of the unit
mask — does not recur.

### Phase 4 measurement

Same fixture as #737: 3 × 30 s × 16-flow iperf3, client
`cluster-userspace-host`, target `172.16.80.200`, CoS fixture
`test/incus/cos-iperf-config.set` applied, fw0 primary,
`net.ipv4.tcp_ecn=1` end-to-end. Per-flow CoV = per-second bps
stdev / mean per stream, mean across streams (16 streams per run).

Per-run raw values:

| Run | Ratio | Retrans / 30 s | CoV mean | CoV max |
|---|---|---|---|---|
| Pre  1 | 1.370× | 198,317 | 16.3% | 26.4% |
| Pre  2 | 1.365× | 186,389 | 15.3% | 26.9% |
| Pre  3 | 1.383× | 245,724 | 18.9% | 27.0% |
| Post 1 | 1.288× | 264,493 | 17.4% | 27.6% |
| Post 2 | 1.492× | 179,843 | 16.7% | 32.5% |
| Post 3 | 1.419× | 257,562 | 14.6% | 25.4% |

Aggregate:

| Metric | Pre-pin mean | Post-pin mean | Δ |
|---|---|---|---|
| Rate ratio (max/min per-flow) | 1.373× | 1.400× | +2% (worse, within noise) |
| Retransmits / 30 s | 210 k | 234 k | +11% (worse, within noise) |
| Per-flow CoV mean | 16.8% | 16.2% | -0.6 pp (better, within noise) |
| Per-flow CoV max | 26.8% | 28.5% | +1.7 pp (worse, within noise) |

### Decision

Per #712's keep/revert/defer thresholds (also cited verbatim in the
#741 task brief):

- **Keep** requires: ratio improves ≥ 5%, OR per-flow CoV mean drops
  ≥ 3 pp on 2+ runs, OR retrans drops ≥ 15%. **None satisfied.**
- **Revert** if no metric moves above thresholds. Three of four
  metrics moved in the *worse* direction within noise; CoV mean
  improved 0.6 pp, far below the 3 pp threshold.
- **Defer** is for "small movement without any metric going worse".
  That condition is not met either — ratio + retrans + CoV max all
  regressed.

**Decision: revert the directive.** Same engineering outcome as #737,
different mechanism. #737 revert was forced by the pin logic bug;
#741 revert is forced by the hardware. The recipe lives on as design
intent; the next lever is #739 (kernel cmdline isolcpus/nohz_full).

### Why the pin doesn't help on this lab

IRQ layout sampled mid-run (abbreviated from `/proc/interrupts`):

- `virtio11-input.0..5` (one of the NICs) — each pinned to its own
  CPU across CPUs 0-5, each carrying tens of thousands of interrupts
  per run.
- `virtio12-input.0..5` — same 1-per-CPU spread, hundreds of
  thousands of interrupts per CPU per run (LAN-side).
- `virtio5-virtqueues` → CPU 2, 65 k interrupts.

CPUs 2-5 carry virtio RX interrupts for four of the six virtio
queues; moving xpfd workers onto those CPUs collides with the same
softirq work that was running there before. The pin moves the
workload alongside its IRQs rather than away from them. To actually
separate the worker from kernel timer + softirq preemption you need
either (a) `isolcpus=2-5` on the cmdline (Option B, #739), or (b)
`ethtool`-level RSS reshape to park the RX queues on CPUs 0-1 so
CPUs 2-5 are truly quiet (out of scope per the recipe).

Until one of those lands, the 14-18% per-flow CoV on this lab is the
floor for `CPUAffinity=` alone.

## Gotchas the deploy wipes

The cluster deploy path (`cluster-setup.sh deploy`) wipes the CoS
config every run — the bootstrapped `xpf.conf` does not carry the
iperf CoS fixture. After every deploy, re-apply:

```bash
./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0
```

The loader script lives at `test/incus/apply-cos-config.sh` and is
documented inline. It is intentionally strict on `load merge` / `commit`
since #716 — if you see a validation error, stop and investigate rather
than re-running. The accompanying fixture at
`test/incus/cos-iperf-config.set` covers both `family inet` and
`family inet6` classifier state.

See also the "CoS deploy preserves config" bullet in
[`engineering-style.md`](engineering-style.md#project-specific-reminders).

## 1 Gbps queue over-throttle fix (post-#754)

**Measured 2026-04-18.** This section records the live measurement
around the #754 rate-aware per-flow ECN threshold change. Read the
#754 issue body for the root-cause design brief; the numbers here are
the empirical keep/revert evidence.

### Context

The pre-#754 per-flow threshold was `share_cap × 1/5`. On the 16-flow
/ 1 Gbps exact queue that landed at ~15 KB per flow — right in TCP
cubic's 8–80 KB steady-state cwnd operating band. Every cwnd-growth
attempt ran the flow's bucket past the mark threshold, so ECN CE
fired continuously and TCP could not hold cwnd high enough to fill
its share.

The fix re-parameterises the per-flow arm to `fair_share_rate ×
COS_ECN_MARK_HEADROOM_MS / 1000`, clamped into
`[COS_FLOW_FAIR_MIN_SHARE_BYTES, share_cap]`. At 62.5 Mbps fair share
(1 Gbps / 16 flows) with 5 ms headroom that yields a 39 KB threshold
— near the top of the cwnd operating band, so marks only fire on
real bursts. At 625 Mbps fair share (10 Gbps / 16 flows) the same
formula gives 391 KB, scaling with the queue's drain rate. The
aggregate arm keeps the `buffer_limit × 1/5` fraction — `buffer_limit`
is sized as `rate × residence` upstream so it scales correctly in
the buffer axis.

### Phase 1 — pre-fix baseline (origin/master `e8e7533a`)

16-flow iperf3, 30 s, `cluster-userspace-host` → `172.16.80.200`,
`tcp_ecn=1` end-to-end, CoS fixture via
`./test/incus/apply-cos-config.sh`. Queue 4 (`iperf-a`, 1 Gbps cap,
1.19 MB buffer).

| Run | Port | Duration | Aggregate | Rate ratio (max/min) | Retrans |
|---|---|---|---|---|---|
| 1 | 5201 | 30 s × 16 | **1.055 Gbps** | 1.534× | 162,145 |
| 2 | 5201 | 30 s × 16 | **1.179 Gbps** | 1.487× | 284,734 |
| 3 | 5201 | 30 s × 16 | **1.024 Gbps** | 1.476× | 123,527 |
| — | 5202 | 30 s × 16 | **9.542 Gbps** | 5.533× | 8 |
| — | 5201 | 5 s × 1 | **1.447 Gbps** | — | 23,522 |

Pre-fix queue-4 counter snapshot (accumulated):
`flow_share_drops=13 229 225, buffer=0, ecn_marked=16 366 893`.

Counter deltas over the ~125 s of Phase 1 workload:
`flow_share_drops=682, buffer=0, ecn_marked=243 307`.

**Observation that contradicted the #754 hypothesis.** The issue body
predicted pre-fix 5201 aggregate ≈ 0.60 Gbps (60 % of cap). At the
time of my measurement (post-#750 head), the baseline was already
delivering 1.02–1.18 Gbps across three runs — the single-flow reached
1.45 Gbps, which is ABOVE the 1 Gbps cap, indicating the CoS
scheduler was not rate-limiting 5201 to its configured cap at the
time of the baseline snapshot. This means the symptom described in
#754 had already shifted between issue-writing and live measurement;
the rate-aware fix was therefore applied against a workload that was
not exhibiting the #754 dominant failure mode.

### Phase 3 — post-fix measurement

Same fixture, `pr/754-rate-aware-ecn-threshold` deployed via
`BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
./test/incus/cluster-setup.sh deploy all`. CoS re-applied, counters
baseline captured at T0.

| Run | Port | Duration | Aggregate | Rate ratio (max/min) | Retrans |
|---|---|---|---|---|---|
| 1 | 5201 | 30 s × 16 | **1.110 Gbps** | 1.449× | 184,469 |
| 2 | 5201 | 30 s × 16 | **1.126 Gbps** | 1.277× | 188,467 |
| 3 | 5201 | 30 s × 16 | **1.113 Gbps** | 1.455× | 215,678 |
| — | 5202 | 30 s × 16 | **9.542 Gbps** | 4.515× | 0 |
| — | 5201 | 5 s × 1 | **0.956 Gbps** | — | 0 |

Counter deltas during the 3 × 30 s 5201 runs (90 s of queue-4
workload, before the 5202 run):
`flow_share_drops_delta = +828, buffer_drops_delta = 0,
ecn_marked_delta = +101 260`.

Normalised per-second comparison with Phase 1 (Phase 1 queue-4
workload ≈ 95 s, Phase 3 = 90 s):

| Counter | Phase 1 (per 30 s) | Phase 3 (per 30 s) | Δ |
|---|---|---|---|
| flow_share_drops | ~215 | ~276 | **+28 %** |
| ecn_marked | ~76 834 | ~33 753 | **−56 %** |
| buffer_drops | 0 | 0 | unchanged |

### Keep / revert decision

Against the #754 acceptance criteria:

| Criterion | Target | Measured | Met? |
|---|---|---|---|
| 5201 aggregate ≥ 0.95 Gbps on ≥ 2 of 3 runs | 0.95 Gbps | 1.11, 1.13, 1.11 Gbps | YES (3/3) |
| Single-flow 5201 reaches ≥ 900 Mbps | 900 Mbps | 955 Mbps | YES |
| Rate ratio ≤ 1.58× | 1.58× | 1.28–1.45× | YES |
| 5202 aggregate ≥ 9.12 Gbps | 9.12 Gbps | 9.54 Gbps | YES |
| `flow_share_drops` Δ drops ≥ 80 % | −80 % | **+28 %** | **NO** |
| `ecn_marked` Δ drops ≥ 50 % | −50 % | −56 % | YES |
| `cargo test` suite green | pass | pass (700 + 26 ECN) | YES |

Six of seven criteria pass. The `flow_share_drops` criterion is the
one that fails: the counter went up 28 % rather than down 80 %. The
mechanism is predictable — the new per-flow threshold sits at 39 KB
instead of ~15 KB, so ECN marks fire much less often (confirmed by
the 56 % drop in `ecn_marked`) and TCP cwnd grows unimpeded further
into the per-flow share cap before being hard-dropped by
`flow_share_exceeded`. In the regime where aggregate throughput is
already at cap, reducing marker pressure pushes drops from the
"marker fires, TCP halves cwnd gracefully" mode into the "TCP hits
cap, packet drops, recovery" mode. The trade-off is visible in the
counter delta even though the primary throughput metric is at target.

**Decision: REVERT** per the #754 §"Acceptance criteria" language
("Keep if ALL"). The primary #754 symptom (0.60 Gbps at cap) was not
reproducible on the measured baseline (already at 1.02–1.18 Gbps),
so the rate-aware fix cannot "move" the primary metric in the way
the issue predicted. The ecn_marked reduction (−56 %) is real and
structurally justified by the rate-aware shape, and six of the seven
acceptance-criteria thresholds are met — but the
`flow_share_drops ≥ 80 % reduction` bar is a hard ALL-must-hold
invariant that was not cleared (the counter went UP 28 % instead).
This is the engineering-style rule — "Do NOT keep the fix if the
data doesn't support it. Revert and file a follow-up if the
rate-aware formula itself needs a different parameterisation" — in
action. The PR landing this section is opened as a measurement
artefact with `--- revert` in the title, so future readers can
re-verify the baseline and the fix shape without having to re-run
the full methodology from scratch.

A follow-up issue should track: (a) why the live workload's
pre-fix delivery drifted from the 0.60 Gbps described in the #754
issue body to the 1.02–1.18 Gbps observed on this measurement, and
(b) whether a smaller `COS_ECN_MARK_HEADROOM_MS` (closer to 2 ms)
would retain the ecn_marked drop without regressing
`flow_share_drops`. Both are parameterisation questions that the
rate-aware shape alone cannot answer.

### Future levers

If the live workload drifts back into the under-delivery regime the
#754 issue described, re-measure with this methodology. The
rate-aware formula is still the right shape; the HEADROOM_MS
parameter (currently 5 ms) can be tuned between 1 ms (more
aggressive marking, lower flow_share_drops) and 50 ms (lazier
marking, more aggregate delivery). The compile-time assertion
`COS_ECN_MARK_HEADROOM_MS ∈ [1, 50]` guards the sensible band; any
future retune outside that envelope fails the build rather than
landing silently.

## Refs

- #704 — umbrella cwnd-collapse symptom
- #709 — owner-worker hotspot (remaining lever for microburst residual)
- #716 — flow-aware admission cap
- #718 — ECN CE marking at CoS admission (Local variant) + Option B CoDel tracker
- #720 — latency-envelope clamp
- #721 — aggregate ECN threshold
- #722 — per-flow ECN mark threshold
- #724 — surface admission drop counters (unblocked this methodology)
- #725 — validation-pipeline gap findings (live data + path forward)
- #727 — ECN marking on Prepared CoS variant (closed the Local-only gap)
- #728 — VLAN-aware L3 offset + threshold tune (resolved the dormant-marker symptom)
- #754 — rate-aware per-flow ECN threshold (this section)
- #712 — CPU pinning + IRQ isolation (Option A measured no-op on this lab; see "CPU pinning layout for the loss lab")
