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
ceiling regardless of scheduler perfection — see §3).

The userspace AF_XDP zero-copy dataplane locks each flow to the
worker that processes its RSS-hashed RX queue (kernel
`xsk_rcv_check()` enforces this — see `userspace-xdp/src/lib.rs`
around line 1305). This is the fundamental architectural basis of
AF_XDP zero-copy. Three independent attempts to redistribute work
across workers have failed:

- **#840** (RSS rebalance): IMPLEMENTED + REVERTED — net-negative
  on fairness (CoV 37.7% with vs 18.5% baseline)
- **#1203** (n-tuple steering / cross-binding): WITHDRAWN as
  architectural anti-pattern
- **#1215** + **#937** (cross-worker shared per-flow signal +
  ingress XDP_REDIRECT): both PLAN-KILLED. The kernel constraint
  that derails #937 is upstream Linux `xsk_rcv_check()` (see
  `net/xdp/xsk.c` in the kernel tree, around line 327 in 7.1-rc),
  which enforces `xs->dev == xdp->rxq->dev` AND
  `xs->queue_id == xdp->rxq->queue_index`. This is the
  fundamental architectural basis of AF_XDP zero-copy and is
  permanent across kernel versions (verified against 5.x, 6.x,
  and 7.1-rc docs). The killed plan-docs preserved on their
  respective PR branches contain the full reviewer findings:
  `feature/1215-per5tuple-fairness` for #1215 v1 KILL,
  `research/937-ingress-xdp-redirect` for #937 feasibility KILL.

Rather than chase an unreachable scalar gate, this contract defines
**structural ceiling** as the reference point. xpf's fairness
quality is measured by **how close it gets to the best possible
fairness for the observed RSS distribution**, not by a fixed CoV
number.

## Vocabulary

- **Per-flow throughput share `sₖ`**: the fraction of total
  measured aggregate throughput received by flow k, over the
  measurement window.
- **Per-flow CoV**: `stddev({sₖ}) / mean({sₖ})` across the flow
  set.
- **Per-worker active-flow distribution `aᵢ`**: the number of
  active flows on worker i during the measurement window. Active
  means `≥ 1` flow contributing measurable throughput on that
  worker.
- **Active worker count `Nₐ`**: count of workers with `aᵢ ≥ 1`.
- **Total worker count `Nᵥ`**: count of workers configured for the
  shared_exact queue under test.
- **Structural fair-share for flow k on worker i**: `1 / (Nᵥ × aᵢ)`
  of total aggregate throughput. Each worker delivers `1/Nᵥ`
  evenly to its `aᵢ` flows.
- **Structural CoV ceiling `Cstruct`**: the population CoV
  computed from the per-flow shares `{1/(Nᵥ × aᵢ)}` weighted by
  flow count. This is the **best achievable CoV** under perfect
  per-worker-fair scheduling on the observed RSS distribution. xpf
  cannot do better than `Cstruct` regardless of scheduler
  perfection.

## Structural CoV ceiling — worked examples

For a 6-worker cluster (`Nᵥ = 6`):

| RSS distribution `{aᵢ}` | Active workers `Nₐ` | Total flows N | Structural CoV `Cstruct` |
|---|---|---|---|
| 2,2,2,2,2,2 (perfectly balanced, 12 flows) | 6 | 12 | 0.00 (0%) |
| 1,1,2,2,3,3 (mild skew, 12 flows) | 6 | 12 | 0.47 (47%) |
| 0,2,2,2,3,3 (one idle, 12 flows) | 5 | 12 | 0.20 (20%) — *with N=12 the idle-worker contribution offsets* |
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

1. **Hard failure — zero-throughput**: `zero_throughput_flow_count == 0`,
   where a zero-throughput flow is one that received `< 1%` of mean
   throughput **for the entire 5+ second steady-state window**
   (excluding warmup; see §5). A flow that's < 1% during warmup but
   recovers does not count.

2. **Per-flow fairness**: `observed_CoV ≤ Cstruct + 0.05`, where
   `Cstruct` is computed from the per-worker active-flow
   distribution measured during the steady-state window.

3. **Aggregate throughput**:
   `observed_aggregate ≥ (Nₐ / Nᵥ) × shaper_rate × 0.95` for
   shaped queues, where the `(Nₐ / Nᵥ)` factor reflects the
   structural ceiling for the observed RSS distribution. For
   non-shaped (best-effort), use the cluster's measured baseline
   for the same `{aᵢ}` distribution from a known-good prior run
   (within ±5%).

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

The same acceptance gates apply uniformly across both saturated
and non-saturated regimes — `Cstruct` is the right reference for
both. The two regimes differ only in *expected observed_CoV*,
not in the gate formula:

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
3. **Zero-throughput flow count**: per the §1 definition.
4. **Per-worker active-flow distribution `{aᵢ}`**: derived from
   per-binding RX-flow counters during the steady-state window.
5. **Computed `Cstruct`**: the structural CoV ceiling for the
   observed `{aᵢ}`.
6. **Saturation determination**: which regime the run is in (per
   §4) and the supporting time-series.
7. **Aggregate throughput** in Mb/s.
8. **Aggregate retransmits**: total retransmits across all senders.
   Diagnostic; not a hard gate.
9. **ECN marks/drops** (if AQM is enabled): total CE marks and
   AQM drops. Diagnostic for future Path 2 v2 work.
10. **Mouse p99 latency** (when mouse probes are present).
11. **Steady-state window**: explicit start/end timestamps,
    excluding the first 5 seconds (warmup) and any final
    sender-shutdown bursts.

## Required metrics — exported in production via gRPC/Prometheus

For production observability, xpf MUST export:

- **`xpf_fairness_regime{queue=...}`** Prometheus gauge: enum
  `{non_saturated, saturated_balanced, saturated_skewed,
   low_n_degenerate}`. Computed from rolling 30-second window of
  per-binding active-flow distribution + saturation determination.
- **`xpf_fairness_cstruct{queue=...}`** gauge: the current
  computed structural CoV ceiling.
- **`xpf_fairness_observed_cov{queue=...}`** gauge: rolling
  observed CoV for the queue.
- **`xpf_fairness_zero_throughput_flows{queue=...}`** counter:
  monotonic count of flows that fell below the zero-throughput
  threshold.

Operators tracking this contract in production monitor the gap
`(observed_cov - cstruct)` and the zero-throughput counter. A
healthy production system has the gap `≤ 0.05` and the counter
flat.

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
- Zero-throughput flow count must not become positive.

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
  latency is a separate SLA in §1.

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
