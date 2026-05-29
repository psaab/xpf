# #1630 cause-2 — §5 instrumented bisection finding

- Issue: #1630 (cause 2: the K/P2/contention-independent ~6% mid-rate
  3g/6g shape residual under `guarantee-rate 0.7`).
- Plan: `docs/research/1630-midrate-residual/plan.md` @ `6edb5b485`
  (branch `research/1630-midrate-residual`), §5.
- Cluster: `loss:xpf-userspace-fw0` (RG0 primary), stock `origin/master`
  `0e5bb3812` daemon. Full `cos-iperf-config.set` applied,
  `oversubscription-policy guarantee-rate 0.7`, shaping-rate 25g.
- Date: 2026-05-29.

## VERDICT: CAUSE-2 = PHYSICS (H-TCP confirmed, sharpened)

The ~6% mid-rate residual is **bursty single-flow-bundle delivery into
the per-worker AF_XDP token bucket — TCP/transport physics outside the
shaper grant/selector**. It is NOT a shaper grant or selector bug. No
grant/selector/lease change recovers it; the shaper grant is fully
available even when a single worker holds the entire class cap and still
under-delivers.

The decisive evidence INVERTS the naive "fair-share" hypothesis: the
deficit is WORST with a single stream/worker and is partially RECOVERED
by adding parallel streams/workers — the opposite of any per-worker
fair-share (H5) under-grant.

## Method (no instrumented build — better than the plan's throwaway build)

The §5 counters the plan proposed to add via an env-gated throwaway
build (`drain_sent` vs `cap_granted`, park rates, root-throttle,
goodput, offered-load) ALREADY EXIST in the stock master control-socket
status block (`CoSQueueStatus`: `drain_sent_bytes`,
`drain_park_queue_tokens`, `drain_park_root_tokens`, `queued_bytes`,
`admission_buffer_drops`, `admission_flow_share_drops`;
`WorkerRuntimeStatus`: `cos_queue_lease_acquire_v8_granted_bytes`,
`wall_ns`). So the bisection ran against the **unmodified production
daemon**, which trivially satisfies the §5.4 instrumentation-perturbation
gate (zero added hot-path code).

Per-class measurement window: solo iperf3 to the class's classifier port
(5203→3g, 5204→6g, 5205→9g), snapshot control-socket status before/after,
compute `drain_sent` delta over the **daemon's own `wall_ns` clock**
(eliminates host-side wall jitter), and read iperf3 goodput JSON. The
mid-run `queued_bytes` sampling is the offered-load / backlog signal.

## §5.0 OFFERED-LOAD GATE (checked FIRST): PASS — class is offered ≥ rate

In every TCP cell the class queue was **persistently backlogged**
(3g ~5 MB, 6g ~13 MB, 9g ~19 MB queued mid-run, never draining to 0),
and UDP at line-rate flood produced massive `admission_buffer_drops`
(20.9M / 15.5M packets). The class is decisively NOT RX/conntrack/forward
-bound below its rate — offered load exceeds shape. The shaper-internal
question is live.

## Table A — TCP solo, full run (30s, -P 12)

| class | drain_sent/shape | good/shape | good/sent | parkR |
|-------|-----------------:|-----------:|----------:|------:|
| 3g    | 0.934 | 0.890 | 0.953 | 0 |
| 6g    | 0.928 | 0.885 | 0.953 | 0 |
| 9g    | 0.925 | 0.881 | 0.953 | 0 |

Daemon-clock confirmation (30s steady window, `wall_ns` denominator):
3g `drain_sent/shape = 0.940`, 6g `= 0.925`. Three repeat 3g runs:
0.938 / 0.940 / 0.954 — reproducible.

Reading:
- `good/sent = 0.953` is **rock-constant = L2 framing overhead**
  (66 B L2/L3/L4 header over ~1448 B TCP MSS ≈ 4.4% + iperf accounting).
  The bytes the shaper SENDS leave the NIC; there is no loss between send
  and wire. The residual is NOT at the goodput-vs-send layer.
- `parkR = 0` everywhere — the **root meter never throttles** a solo
  class (§5.3 satisfied). Not a root-shaper fix.
- The residual lives between **shape and drain_sent**
  (`drain_sent/shape ≈ 0.93`): the shaper TX-output counter is ~6-7%
  below `rate×wall` even with a continuously backlogged queue.

## Table B — UDP offered-load (line-rate flood)

| class | drain_sent/shape | udp lost% | admission_buffer_drops | flow_share_drops |
|-------|-----------------:|----------:|-----------------------:|-----------------:|
| 3g    | 0.881 | 76.6 | 20,918,448 | 1,885,668 |
| 6g    | 0.675 | 65.5 | 15,528,821 | 1,332,891 |

Reading: UDP does **NOT** saturate the class to ≥95% — it is WORSE than
TCP. The UDP loss is `admission_buffer_drops` + `admission_flow_share_
drops` at the **enqueue** site (UDP floods past buffer capacity with no
backpressure), so UDP is not a clean test of shaper *output* capacity.
But it decisively confirms the offered-load gate (offered ≫ rate) and
rules out "TCP pacing caps below a shaper ceiling that UDP could reach":
flooding the queue does NOT push drain_sent above the TCP number. The
limiter is the shaper's per-worker drain/bucket-fill, not TCP's send
rate.

## Table C — THE DECISIVE DISCRIMINATOR: stream/worker parallelism (3g)

| streams (-P) | workers active | drain_sent/shape | backlog |
|-------------:|---------------:|-----------------:|--------:|
| 1  | 1 | **0.878** | 1.1 MB |
| 4  | 2 | 0.918 | 2.1 MB |
| 12 | 6 | 0.949 | 6.6 MB |

This INVERTS the fair-share (H5) hypothesis:

- A **single stream on a single worker (0.878) is the WORST**, despite
  that one worker holding the **entire class cap** (`my_share = cap` when
  `total_flows = 1`). No fair-share split, full grant available — and it
  still under-delivers by 12%.
- Delivery **improves monotonically with parallelism**
  (0.878 → 0.918 → 0.949). Adding independent flow/worker fill-sources
  statistically smooths the per-worker bucket fill toward shape.

H5 (per-worker fair-share rounding) predicts the OPPOSITE (sharding
causes the deficit). H5 is **falsified**. The grant ceiling is not the
binding limit (single worker gets full cap, under-consumes it).

## Mechanism (sharpened H-TCP)

The per-worker exact-class token bucket (`queue.hot.tokens`, topped to
`lease_bytes = rate×200µs` per visit) is fed by the TCP flow-bundle's
ACK-clocked, 50µs-quantized delivery. A single TCP flow-bundle on one
worker cannot keep that worker's bucket continuously full enough to drain
at exactly `rate` — the bucket alternates token-rich/just-drained in
bursts, and the drain visit that finds `queue.hot.tokens < head_len`
parks (counter `drain_park_queue_tokens` fires 19K–117K/s). Across more
workers/flows, the independent burst phases average out and delivery
approaches shape. This is transport/delivery physics in the AF_XDP
per-CPU + token-bucket interaction, recovered only by parallelism — NOT a
grant, selector, lease, or root-meter defect.

All three statically-derived shaper mechanisms (timer-wheel park floor,
lease-target, waterfill Phase-1 relegation) were already code-falsified
in the research rounds (plan §3). This measurement confirms the leading
remaining hypothesis (H-TCP) and adds the parallelism discriminator
(Table C) that no shaper-internal mechanism can explain.

## Recommendation

1. **Document the floor** in `docs/fairness-regimes.md`: under
   `guarantee-rate 0.7`, a single-flow-bundle mid-rate exact class
   delivers ~88-94% of shape; the residual is bursty per-worker
   bucket-fill physics, recovered by parallelism, not a shaper bug.
2. **Re-scope Gate-1**: cause-1's carry owns the lowest classes
   (100m/1g, the genuine grant-bound loss). Re-frame the mid-rate
   (3g/6g) Gate-1 target to an achievable bound (e.g. ≥95% only at
   sufficient flow/worker parallelism, or accept ~90% for solo single-
   flow-bundle) rather than an unconditional 95%-solo target.
3. **PLAN-KILL the cause-2-shaper-fix.** No grant/selector/lease change
   recovers a deficit that is worst at full single-worker grant and
   recovered by parallelism. (Optional future: a delivery-smoothing /
   finer-than-50µs service-granularity experiment MAY narrow it, but it
   is transport physics, not a shaper defect, and is out of cause-2's
   shaper-fix charter.)

## Cluster state

No source was modified (no instrumented build was needed). The daemon
was left untouched at `origin/master`; CoS config intact; fw0 RG0
primary; all test iperf3 drained. Cluster released for the cause-1
engineer's Gate-1 run.
