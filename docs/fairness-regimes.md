# xpf Fairness Regimes — Product Contract

This document defines what xpf promises about per-flow fairness on the
userspace AF_XDP dataplane. It is the answer to "is xpf fair?" — and
the answer is regime-dependent, not a single number.

## Why a regimes contract

A single per-flow CoV gate (e.g. ≤20%) is not satisfiable across all
operating regimes simultaneously on this architecture. The userspace
AF_XDP zero-copy dataplane locks each flow to the worker that
processes its RSS-hashed RX queue (kernel `xsk_rcv_check()` enforces
this; see `userspace-xdp/src/lib.rs:1305-1312`). This is not a bug —
it is the fundamental architectural basis of AF_XDP zero-copy.

Three independent attempts to redistribute work across workers have
failed:

- **#840 (RSS rebalance)** — implemented and reverted. Net-negative
  on fairness (CoV 37.7% with vs 18.5% baseline).
- **#1203 (n-tuple steering / cross-binding)** — withdrawn as
  architectural anti-pattern.
- **#1215 + #937 (cross-worker shared per-flow signal + ingress
  XDP_REDIRECT)** — both PLAN-KILLED with kernel-source citations.
  See `docs/pr/1215-per5tuple-fairness/plan.md` and
  `docs/pr/937-ingress-xdp-redirect/feasibility.md`.

Rather than chase an unsatisfiable scalar gate, this contract defines
five operating regimes and the per-regime guarantee. Operators get
honest expectations; engineers get measurable acceptance criteria;
future fairness work has a baseline to improve against.

## Fairness regimes

| Regime | Definition | Per-flow CoV target |
|---|---|---|
| **non-saturated** | Offered load < cluster capability; per-class shaper not at cap | ≤ 20% |
| **saturated balanced RSS** | At per-class shaper cap; flows distributed roughly evenly across workers (max-worker / min-worker active-flow count ≤ 1.5×) | ≤ 25% |
| **saturated RSS-skewed** | At cap; flow distribution skewed (max-worker / min-worker ratio > 1.5×; e.g. 1+3 across 2 workers, or 0/2/2/2/3/3 across 6) | ≤ 30% **OR** explicitly flagged as RSS-skewed regime in the report |
| **low-N degenerate** | Flow count N ≤ worker count; one or more workers idle | Per-active-flow CoV ≤ 25%; idle-worker count flagged |
| **high-fan-in** | N ≥ 4× worker count (e.g. P=128 on 6 workers) | Aggregate-throughput gate (≥ 90% of cluster line rate) takes precedence; per-flow CoV expected to widen due to per-worker SFQ bucket collision and TCP cwnd jitter |

The differentiator between regimes is **regime detection by the
test harness**, not regime selection by xpf. xpf's behavior is
unchanged; the harness identifies which regime a workload is in via
per-binding RX flow counts and labels the run.

## Required metrics

Any fairness measurement run must report at minimum:

1. **Per-flow throughput distribution**: min, p25, median, p75, max
   in Mb/s. Stream count (N).
2. **Per-flow CoV**: stddev / mean across the flow set.
3. **Zero-throughput flow count**: number of streams that received
   < 1% of mean throughput. **This is a hard failure** — any run with
   `zero-throughput-flow-count > 0` fails regardless of other gates.
4. **Aggregate retransmits**: total retransmits across all senders
   during the measurement window. Diagnostic; not a hard gate.
5. **ECN marks/drops**: total CE marks and AQM drops if ECN is in use.
   Diagnostic for AFD-style work; not a hard gate today.
6. **Mouse p99 latency** (for runs that include mouse-flow probes
   alongside elephants): TCP-connect+echo p99 latency on a paced
   probe stream. **Separate SLA gate**, not subsumed by per-flow CoV.
7. **Per-worker active-flow distribution**: max/min/median active
   flows per worker, derived from per-binding RX counters. Required
   to label the regime (balanced vs skewed RSS).
8. **Aggregate throughput**: total Mb/s across all flows.

## Acceptance gates

A measurement run **PASSES** iff:

| Gate | Condition |
|---|---|
| **Zero-throughput** | `zero_throughput_flow_count == 0` (hard failure on any positive count) |
| **Per-flow CoV** | Within the regime's target (see table above) OR run is explicitly labeled as RSS-skewed regime with per-worker distribution attached |
| **Mouse p99** | Within ±15% of idle-baseline (separate gate; only applies when mouse probes are present in the run) |
| **Aggregate throughput** | ≥ 90% of cluster line rate for the configured per-class shaper, OR documented regression with cause attached |

A run that satisfies the per-flow CoV target trivially because it ran
the **wrong regime** for the workload (e.g., reports ≤20% CoV but
ran in non-saturated mode when the workload was meant to be saturated)
**does not pass** — the regime label is part of the gate. The test
harness must detect the regime from the per-worker active-flow
distribution and apply the matching target.

### Regression bounds

For changes that should not affect fairness:

- Per-flow CoV must not regress more than 2 percentage points vs the
  prior tip in the same regime.
- Aggregate throughput must not regress more than 5%.
- Mouse p99 must not regress more than 10%.
- Zero-throughput-flow-count must not become positive.

For changes that explicitly target fairness improvement:

- The PR body must declare the targeted regime(s).
- Improvement is measured per-regime. A change that improves
  saturated-RSS-skewed CoV but regresses non-saturated CoV is a
  trade-off the reviewer must accept explicitly.

## Non-goals

xpf does **not** claim, and this contract does **not** require:

- **Global per-5-tuple equality across arbitrary RSS placement.**
  Without hardware steering, cross-worker arbitration, or sender
  backpressure (ECN response), this is structurally unreachable on
  AF_XDP zero-copy. See the killed approaches at
  `docs/pr/1215-per5tuple-fairness/plan.md`,
  `docs/pr/937-ingress-xdp-redirect/feasibility.md`.
- **Equal per-flow throughput within a single RSS-skewed deployment**
  beyond what per-worker MQFQ scheduling can achieve. The
  worst-case 1+3 distribution gives the lone-worker flow at most
  1/2 share and the 3-flow worker's flows 1/6 share each, regardless
  of per-worker scheduler perfection.
- **A single CoV number that holds across all workloads.** The
  table above replaces this aspiration with per-regime gates.
- **Mouse latency p99 inside the per-flow CoV gate.** Mouse latency
  is a separate SLA; mixing it in the CoV gate is a category error.

## How operators interpret this contract

The contract is a measurement framework, not a tuning manual.
Operators should not need to do anything to "achieve fairness." The
contract tells xpf engineers and reviewers when a fairness change
is acceptable to ship.

Operators do see per-worker / per-flow statistics in the gRPC and
Prometheus surfaces (existing `show class-of-service` family of
commands). These are the same metrics this contract requires, so an
operator running iperf3 against the cluster can compute CoV and zero-
throughput counts directly.

## Future research (non-binding)

The killed-approaches list above identifies one mechanism that may
in the future allow tightening saturated-RSS-skewed gate toward the
non-saturated target: a **race-safe AFD/CSFQ-style ECN overlay** with
per-worker-sharded estimators and epoch-published windows. This is
tracked separately as #1211 and is **not part of this contract**. If
that work succeeds, this document gets a regime gate update; if it
doesn't, this document is the steady-state contract.

## Document location and update policy

This file lives at `docs/fairness-regimes.md` and is the single
source of truth for the contract. Updates require:

- Plan-review (triple-review per the standard methodology).
- Smoke matrix on the loss userspace cluster, run for each regime
  this contract names — a contract that doesn't measurably hold on
  the test bench is broken.
- Memory entry: any change to the gate values updates
  `feedback_smoke_*` memory entries that reference numeric targets.
