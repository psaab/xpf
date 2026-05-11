# xpf Fairness Regimes — Product Contract

This document defines what xpf promises about per-flow fairness on the
userspace AF_XDP dataplane. The contract is **structural**: it holds
xpf accountable to the best fairness physically achievable on its
architecture, not to a fixed CoV number that has no mapping to the
underlying constraints.

## Why a structural contract

A single per-flow CoV gate (e.g. ≤20%) is not satisfiable across
workloads on this architecture, and a fixed-per-regime CoV gate
(e.g. ≤30% on saturated-RSS-skewed) is mathematically inconsistent
with the structural ceilings (a 1+3 distribution has a ~58% CoV
ceiling regardless of scheduler perfection — see "Structural CoV
ceiling — worked examples" below).

The userspace AF_XDP zero-copy dataplane locks each flow to the
worker that processes its RSS-hashed RX queue (the upstream Linux
kernel enforces this in `net/xdp/xsk.c`,
where `xsk_rcv_check()` validates `xs->dev == xdp->rxq->dev` and
`xs->queue_id == xdp->rxq->queue_index` before delivery; this
codebase's local comment at `userspace-xdp/src/lib.rs` around
line 1305 records the empirical effect of that validation —
namely that hashing to a different userspace queue silently
strands packets). This is the fundamental architectural basis of
AF_XDP zero-copy. Three independent attempts to redistribute work
across workers have failed:

- **#840** (RSS rebalance): IMPLEMENTED + REVERTED — net-negative
  on fairness (CoV 37.7% with vs 18.5% baseline)
- **#1203** (n-tuple steering / cross-binding): WITHDRAWN as
  architectural anti-pattern
- **#1215** + **#937** (cross-worker shared per-flow signal +
  ingress XDP_REDIRECT): both PLAN-KILLED. The kernel constraint
  that derails #937's clean form is upstream Linux's per-socket
  device + queue validation in `net/xdp/xsk.c`:
  `xsk_rcv_check()` verifies `xs->dev == xdp->rxq->dev` and
  `xs->queue_id == xdp->rxq->queue_index` before delivery.
  The durable narrow claim: **arbitrary cross-queue XSKMAP
  delivery is not supported in current Linux**; leased/peered
  exceptions do not provide the redistribution this design needs.
  The killed plan-docs are evidence trail only — they live on
  their respective non-merged PR branches, not on master, so a
  fresh checkout of this contract's branch will not show those
  paths. They are linked here for engineers tracing the kill
  rationale; they do not gate the contract:
  - `feature/1215-per5tuple-fairness:docs/pr/1215-per5tuple-fairness/plan.md`
    (#1215 v1 KILL with Codex `task-mounv6zx` + Gemini `task-mounvopl`)
  - `research/937-ingress-xdp-redirect:docs/pr/937-ingress-xdp-redirect/feasibility.md`
    (#937 feasibility KILL with Codex `task-mouozcic` + Gemini `task-mouozuvq`)

Rather than chase an unreachable scalar gate, this contract defines
**structural ceiling** as the reference point. xpf's fairness
quality is measured by **how close it gets to the best possible
fairness for the observed RSS distribution**, not by a fixed CoV
number.

## Vocabulary

- **Per-flow throughput share `sₖ`**: flow k's measured
  throughput divided by the **mean** measured per-flow
  throughput across the flow set during the steady-state
  window. Equivalently `sₖ = Tₖ / mean(T)`. Defined this way
  the shares are **dimensionless** and the sample mean is 1 by
  construction; CoV is `stddev({sₖ})` which is also `stddev/mean`
  on the raw `Tₖ`.
- **Per-flow CoV**: `stddev({sₖ}) / mean({sₖ})` across the flow
  set.
- **Per-worker active-flow distribution `aᵢ`**: the number of
  active flows on worker i during the measurement window. Active
  means `≥ 1` flow contributing measurable throughput on that
  worker.
- **Active worker count `Nₐ`**: count of workers with `aᵢ ≥ 1`.
- **Total worker count `Nᵥ`**: count of workers configured for the
  shared_exact queue under test.
- **Structural fair-share for flow k on worker i** (only
  defined for active workers, `aᵢ ≥ 1`): under perfect per-
  worker-fair scheduling, flow k gets `Tₖ_struct = (S/Nᵥ) / aᵢ`
  where `S` is the cluster aggregate. Idle workers contribute
  zero flows so they don't appear in this denominator (no
  division by zero).
- **Structural CoV ceiling `Cstruct`**: the population CoV
  computed from the per-flow throughputs `{Tₖ_struct}` across
  the active flow set, normalized to mean=1 (equivalent to
  `stddev({Tₖ_struct}) / mean({Tₖ_struct})`). This is the **best
  achievable CoV** under perfect per-worker-fair scheduling on
  the observed RSS distribution. xpf cannot do better than
  `Cstruct` regardless of scheduler perfection.

  Worked formula: with `Nᵥ` workers and active flow distribution
  `{aᵢ}` (flows per active worker), expand to per-flow shares
  `{1/aᵢ : repeated aᵢ times for each active worker i}` (after
  factoring out the `S/Nᵥ` constant which doesn't affect CoV),
  then compute population stddev over this multiset divided by
  its population mean.

## Structural CoV ceiling — worked examples

For a 6-worker cluster (`Nᵥ = 6`):

| RSS distribution `{aᵢ}` | Active workers `Nₐ` | Total flows N | Structural CoV `Cstruct` |
|---|---|---|---|
| 2,2,2,2,2,2 (perfectly balanced, 12 flows) | 6 | 12 | 0.00 (0%) |
| 1,1,2,2,3,3 (mild skew, 12 flows) | 6 | 12 | 0.47 (47%) |
| 0,2,2,2,3,3 (one idle, 12 flows) | 5 | 12 | 0.20 (20%) — *the per-flow share set is {1/2 × 6, 1/3 × 6}; spread narrower than 1,1,2,2,3,3 because the high-share 1/1 flows from the {1,1} workers are absent. The idle worker is excluded from the per-flow set (it has zero flows), not "compensating" for anything.* |
| 1,3,0,0,0,0 (severe skew, 4 flows) | 2 | 4 | 0.58 (58%) |
| 6,0,0,0,0,6 (degenerate, 12 flows) | 2 | 12 | 0.00 (0%) — *both workers fully loaded with 6 flows each* |

The contract gate is **observed CoV ≤ Cstruct + ε** where `ε` is
the implementation-quality margin (set to `0.05` = 5 percentage
points).

The harness must compute `Cstruct` from the observed `{aᵢ}` and
then check `observed_CoV ≤ Cstruct + 0.05`. This makes the gate
**meaningful for any RSS distribution** and rules out the
mathematical inconsistency of fixed CoV bands.

## Acceptance gates

A measurement run **PASSES** iff ALL of:

1. **Hard failure — starved flows**: `starved_flow_count == 0`,
   where a **starved flow** is one that received `< 1%` of mean
   per-flow throughput across the **entire steady-state window**
   (per "Steady-state measurement window" below: 60+ second window,
   warmup and final-burst excluded). A flow that drops below 1%
   transiently but recovers does not count. The metric is named
   "starved" rather than "zero-throughput" to avoid implying
   strict 0 Mb/s.

2. **Per-flow fairness**: `observed_CoV ≤ Cstruct + 0.05`, where
   `Cstruct` is computed from the per-worker active-flow
   distribution measured during the steady-state window.

3. **Aggregate throughput** (saturated regime only):
   For runs labeled saturated (per "Saturation detection" below): the
   structural-throughput gate
   `observed_aggregate ≥ (Nₐ / Nᵥ) × shaper_rate × 0.95` applies
   for shaped queues. For non-shaped (best-effort) saturated
   runs: ±5% of the cluster's measured baseline for the same
   `{aᵢ}` distribution from a known-good prior run.

   For runs labeled **non-saturated**: aggregate throughput is
   NOT gated. The contract assumes non-saturated runs are
   cwnd-bound or application-bound; the test simply records
   `observed_aggregate` for diagnostic context but does not
   apply a fail/pass on it. Per-flow fairness (Gate 2),
   starved-flow (Gate 1), and mouse p99 (Gate 4) remain
   active for non-saturated runs.

   Rationale: non-saturated runs by definition do not push
   enough load to fill the structural cap; failing them on a
   throughput floor would be a category error.

4. **Mouse p99** (only when mouse probes are present): mouse
   TCP-connect+echo p99 latency `≤ 2 × idle_baseline`, where
   `idle_baseline` is the same probe against the cluster with no
   elephant traffic.

A run that satisfies any single gate while failing another **does
not pass**. There is no "OR flagged" escape clause; if a gate
cannot be met, the contract requires either a code change or a
documented contract amendment via this file (with its own
plan-review).

### Saturation detection (numeric, scaled to structural cap)

A run is in the **saturated regime** iff the observed aggregate
throughput stays `≥ 95%` of the **structural cap** for at least
80% of the steady-state measurement window (in 1-second buckets).

The structural cap is **`(Nₐ / Nᵥ) × shaper_rate`**, NOT the raw
shaper rate. Without this scaling, a structurally-saturated
RSS-skewed run (e.g. `Nₐ=2, Nᵥ=6`, can only physically reach
~33% of unscaled cap) would always be labeled non-saturated.
Scaling makes "saturated" mean "consuming all the bandwidth
the active workers can deliver".

Gates 1, 2, and 4 apply to **all** runs (saturated and
non-saturated). Gate 3 (aggregate throughput) applies to
**saturated runs only** (see Gate 3 above). The two regimes
differ only in *expected observed_CoV*, not in the CoV gate
formula:

- **Saturated**: `observed_CoV` will approach `Cstruct` from
  below as the per-worker scheduler does its job. Pass iff the
  gap `observed_CoV - Cstruct ≤ 0.05`.
- **Non-saturated**: flows are cwnd-bound, not shaper-bound.
  `observed_CoV` is typically near 0 because flows aren't
  competing for tokens. `Cstruct` for the observed `{aᵢ}`
  may still be high (it's a pure function of `{aᵢ}` and `Nᵥ`,
  unrelated to cwnd or saturation state). The gate passes
  trivially because `observed_CoV << Cstruct`, leaving a
  large negative gap.

The gate formula does NOT change between regimes. Saturation
labeling is for diagnostic context (operators can see "we're
in saturated regime and CoV is at the structural floor") but
does not change pass/fail.

## Required metrics — exported from the harness

Any fairness measurement run MUST report:

1. **Per-flow throughput**: `min, p25, median, p75, max` (Mb/s) and
   stream count `N`.
2. **Per-flow CoV**: `stddev / mean` across the steady-state window.
3. **Starved flow count**: per the Gate 1 definition above.
4. **Per-worker active-flow distribution `{aᵢ}`**: count of
   distinct 5-tuples observed on each worker during the steady-state
   window. Single-class harness runs can use
   `xpf_userspace_binding_active_flow_count{binding_slot, queue_id,
   worker_id, iface}` filtered to the bottleneck direction. Mixed
   workload and production class-specific runs should use
   `xpf_userspace_cos_active_flow_count{ifindex, queue_id, worker_id}`
   for the selected egress CoS queue. These live metrics define
   "active" as a flow-cache entry touched within the active-flow
   recency window, currently 10 debug epochs (about 650 ms), so `{a_i}`
   is an operational proxy for worker/RSS placement rather than a
   throughput-derived ≥1% cutoff.
5. **Computed `Cstruct`**: the structural CoV ceiling for the
   observed `{aᵢ}`.
6. **Saturation determination**: which regime the run is in (per
   the "Saturation detection" section) and the supporting
   time-series.
7. **Aggregate throughput** in Mb/s.
8. **Aggregate retransmits**: total retransmits across all senders.
   Diagnostic; not a hard gate.
9. **ECN marks/drops** (if AQM is enabled): total CE marks and
   AQM drops. Diagnostic for future Path 2 v2 work.
10. **Mouse p99 latency** (when mouse probes are present).
11. **Steady-state window**: explicit start/end timestamps,
    excluding the first 5 seconds (warmup) and any final
    sender-shutdown bursts.

Mixed-workload CoS validation MUST run at least two classes
concurrently under one metrics scrape so class-specific `{a_i}` cannot
silently collapse back to the per-binding aggregate. The canonical
harness command is:

```bash
COS_IFINDEX=<egress-ifindex> ./test/incus/fairness-harness.sh --mixed-cos
```

With the default symmetric CoS fixture this runs port 5201
(`iperf-a`, queue 4) and port 5202 (`iperf-b`, queue 5) concurrently,
then invokes `fairness-eval` twice against the same
`xpf_userspace_cos_active_flow_count` scrape: once for queue 4 and
once for queue 5. Non-canonical fixtures must set `COS_QUEUE_ID` and
`MIXED_COS_QUEUE_ID` explicitly.

## Required metrics — exported in production via gRPC/Prometheus

For production observability, xpf MUST export:

- **`xpf_fairness_saturated{queue=...}`** Prometheus gauge: 0 or
  1. Computed from rolling 30-second window of aggregate
  throughput vs structural cap (per "Saturation detection").
  Diagnostic only — saturation does not change pass/fail of the
  Cstruct gate, but operators may want to know whether their
  workload is actually hitting the shaper. The original v3 enum
  with `{non_saturated, saturated_balanced, saturated_skewed,
  low_n_degenerate}` labels is dropped: with the structural-
  ceiling gate replacing fixed regime bands, distinguishing
  balanced/skewed/degenerate is not load-bearing on pass/fail —
  the per-worker active-flow distribution `{aᵢ}` is the
  underlying signal and is exported separately if the harness
  needs it for context.
- **`xpf_fairness_cstruct{queue=...}`** gauge: the current
  computed structural CoV ceiling.
- **`xpf_fairness_observed_cov{queue=...}`** gauge: rolling
  observed CoV for the queue.
- **`xpf_fairness_starved_flows{queue=...}`** counter:
  monotonic count of flows that fell below the starved-flow
  threshold (< 1% of mean per-flow throughput) over their lifetime.

Operators tracking this contract in production monitor the gap
`(observed_cov - cstruct)` and the starved-flow counter. A
healthy production system has the gap `≤ 0.05` and the counter
flat.

**These Prometheus metrics do not currently exist in the
collector.** They are mandated by this contract and must be
added in a follow-up PR alongside the harness work that computes
`Cstruct` and the rolling-window inputs. Until that PR ships, the
contract is enforced via the test harness only.

## Steady-state measurement window

Every measurement run requires:

- **Warmup**: discard the first 5 seconds. TCP cwnd ramp and ARP/
  ND resolution distort early samples.
- **Window length**: at least 60 seconds. Shorter windows are
  dominated by TCP cwnd jitter and produce noisy CoV.
- **Bucket size**: 1-second buckets for saturation determination
  and for time-series-based regime detection.
- **Final-burst exclusion**: discard the last 1 second to avoid
  sender-side shutdown artifacts.

A run shorter than 60 seconds steady-state cannot pass the per-flow
fairness gate (insufficient samples for stable CoV). The harness
must reject such runs with an explicit error, not pass them
trivially.

## Regression bounds

For changes that should NOT affect fairness:

- `(observed_cov - cstruct)` regression `≤ 0.02` (2 percentage
  points) vs prior tip on the same fixture.
- Aggregate throughput regression `≤ 5%`.
- Mouse p99 regression `≤ 10%`.
- Starved flow count must not become positive.

For changes that explicitly target fairness improvement:

- The PR body must declare the targeted RSS distribution(s).
- Improvement is measured as **reduction in `(observed_cov -
  cstruct)`**, not as absolute CoV. A change that reduces the gap
  on `{1,3}` distribution from `+0.20` to `+0.05` is a clear win;
  a change that drops absolute CoV from 30% to 25% is meaningless
  if the RSS distribution changed too.

## Non-goals

xpf does NOT claim, and this contract does NOT require:

- **Global per-5-tuple equality across arbitrary RSS placement.**
  Without hardware steering, cross-worker arbitration, or sender
  ECN backpressure, this is structurally unreachable on AF_XDP
  zero-copy. The structural CoV ceiling `Cstruct` is a hard
  physical limit set by the per-worker scheduler's ability to
  divide its share equally among its flows.
- **Equal per-flow throughput within a single RSS-skewed
  deployment** beyond what `Cstruct` permits. The 1+3 example
  has a structural minimum CoV of ~58%; xpf cannot do better.
- **A single CoV number that holds across all workloads.** The
  structural ceiling is workload-dependent; the gate is
  workload-relative (`observed_cov ≤ Cstruct + ε`).
- **Mouse latency p99 inside the per-flow CoV gate.** Mouse
  latency is a separate SLA in the "Acceptance gates" Gate 4.

## Document location and update policy

This file lives at `docs/fairness-regimes.md` and is the single
source of truth for the contract. Updates require:

- Plan-review (triple-review per the standard methodology).
- Smoke matrix on the loss userspace cluster, run for fixtures
  that exercise multiple `{aᵢ}` distributions — a contract that
  doesn't measurably hold on the test bench is broken.
- Memory entry: any change to gate values (the `ε = 0.05` margin,
  the saturation threshold, the warmup window) updates
  `feedback_smoke_*` memory entries that reference numeric
  targets.

## Open questions for future contract iteration

- Is `ε = 0.05` (5 percentage points implementation margin) the
  right value? Tighter (e.g. 0.02) would push for better
  scheduler fidelity; looser (e.g. 0.10) accepts more
  implementation noise.
- Should the gate scale `ε` by the structural ceiling itself
  (e.g. `ε = max(0.05, 0.10 × Cstruct)`)? Currently a flat 0.05.
- Should mouse p99 SLA include separate gates for ECN-capable vs
  ECN-stripped flows?
- Is the harness's `{aᵢ}` measurement (per-binding RX flow count)
  trustable, or does it need more scrutiny when a flow's packets
  hash across multiple workers due to cwnd-related RSS
  reordering? (Believed not to happen for TCP, but unverified.)
