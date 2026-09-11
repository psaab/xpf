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

The userspace AF_XDP zero-copy dataplane serves each packet on the
worker whose socket owns the RX queue the NIC delivered it to. By
default that queue is RSS-hashed, so a flow stays on one worker; an
exact ntuple rule can move an established flow to another queue (see
"Hardware steering and the floor"). The queue-to-socket binding
itself cannot move (the upstream Linux
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
  architectural anti-pattern (for what its measurement does and does
  not show at HEAD, see "Hardware steering and the floor" below)
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

## Per-flow CoV floor (RSS multinomial)

`Cstruct` above is the ceiling for *one observed* `{aᵢ}`
distribution. This section gives the **floor on the distribution
itself**: how uneven `{aᵢ}` is *expected* to be when `N` flows are
hashed by RSS into `M` RX queues. The two together bracket the
problem — `{aᵢ}` will not be flat (this section), and given a
non-flat `{aᵢ}` the per-flow CoV cannot beat `Cstruct` (above).

This is a canonical reference for the recurring observation that
`iperf3 -c 172.16.80.200 -p 5210 -P 6` shows a stable bimodal
per-flow split: ~2 flows pinned slow sharing one worker, ~4 flows
solo, ≥1 worker idle. **That is the floor, not a scheduler bug.**
Cross-references: #1333 (symptom report), #1304, #1649 (this
analysis), and the killed cross-worker-rebalance chain
#1215 / #837 / #937 / #840 / #1238 / #1243.

### The floor curve

On the loss userspace cluster the dataplane NIC exposes **M = 6
combined RX queues**, deterministically bound one-per-worker
(RX queue N delivers to the worker whose AF_XDP socket is bound to
queue N — the shim resolves the binding slot straight from the
packet's own arrival queue, `binding_slot()` in
`userspace-xdp/src/binding_index.rs`, and never remaps it; #5173).
RSS hashes each TCP flow's 5-tuple to one of those 6 queues, so
`N` flows land as a **multinomial draw** over `M = 6` bins.

The unevenness of that draw is a pure function of `N` and `M`. Two
useful summaries, both computed by Monte-Carlo (200k–400k trials,
i.i.d. uniform hashing) and confirmed against closed form:

- **CoV of the per-queue occupancy counts** `{aᵢ}` (how skewed the
  worker loading is):

  | N flows (M=6) | E[CoV of `{aᵢ}`] | P(≥1 idle worker) |
  |---:|---:|---:|
  | 2  | 1.55 | 100%  |
  | 6  | 0.87 | 98%   |
  | 12 | 0.62 | 56%   |
  | 18 | 0.50 | 21%   |
  | 24 | 0.44 | 8%    |

  At `N = 6` the count-CoV is ≈ **0.87** and the chance of a
  perfect one-flow-per-queue spread is only
  `6!/6⁶ ≈ 1.54%`. The curve is **monotonically decreasing**:
  highest at small `N` (with `N < M` at least `M − N` queues are
  guaranteed idle, so the occupancy vector is mostly zeros and its
  CoV is very high — ≈ 1.55 at `N = 2`), falling as `N` grows and
  the law of large numbers flattens the bins.

- **Live per-flow throughput CoV** in the **observed skewed case**
  (`-P 6 -p 5210`, ~17%) is lower than the 0.87 occupancy CoV
  because TCP cwnd dynamics and the per-worker scheduler partially
  smooth the count unevenness, and because the common `N = 6`
  realizations are mild — e.g. two-pairs `[2,2,1,1,0,0]` (≈35%) or
  "4 solo + 1 pair" `[2,1,1,1,1,0]` (≈23%) — rather than a
  worst-case pile-up. The ~17% is one such favorable realization,
  mapped
  through `Cstruct` for its `{aᵢ}`. Do not conflate the two
  numbers: 0.87 is the *occupancy* CoV of the multinomial; ~17% is
  the *throughput* CoV of one observed placement. (The
  correspondence does not hold universally: a perfect
  one-flow-per-queue draw has occupancy CoV = 0 while individual
  flow rates can still differ.) Both are on the floor — neither
  indicates a defect.

The shape (high at small `N`, decreasing as `N` grows) is the
takeaway. A small flow count over 6 queues is *expected* to be
bimodal.

### Hardware steering and the floor

The natural question is "the NIC supports flow steering — can we
just steer flows one-per-queue?" It has two answers, measured
separately. No *static* rule set beats the RSS floor for uncoordinated
ephemeral source ports (#1649, below).
Re-placing *established* flows does beat it at HEAD (#9488, "Re-placement
measured at HEAD" below). Whether moving an established flow is
*safe* is an open architectural question, #9778. #1649's findings
(verbatim ethtool evidence in issue #1649, research plan at commit
`36fcd1b8`):

- **The #937/#840-named prerequisite EXISTS.** The mlx5 VF accepts
  exact-5-tuple → RX-queue ntuple rules
  (`ethtool -N ... action <q>` → `Added rule with ID 1023`) and
  masked source-port-residue rules
  (`src-port 0 m 0xfff8 dst-port 5210 m 0x0000`). Rule-table
  capacity is **1024** (probed to exhaustion =
  mlx5 `MLX5E_ETHTOOL_FLOW_SPEC_NUM`, NOT the "32k" #1203 assumed),
  at **~1 ms-class** firmware cost per rule.

- **No static `f(5-tuple) → queue` map beats RSS.** Any rule set
  installed once (residue buckets, RSS-context layouts, a wider
  hashed field) is still a *static hash*: for clients using
  ephemeral source ports it produces i.i.d. queue draws with a
  fixed probability vector — balanced gives exactly the RSS floor,
  imbalanced gives worse. Monte-Carlo confirms masked-residue
  steering lands at CoV ≈ 0.87 (same as RSS) for ephemeral ports,
  worse (≈ 1.05) for the mod-8 layout. It beats the floor *only*
  when the generator deliberately coordinates source-port residues
  with the queue count (`iperf3 --cport` stepping) — a
  controlled-harness artifact, never production traffic.

- **Even placement of `N ≤ M` flows requires negative
  dependence** — steering each new flow *away from* already-occupied
  queues. The SYN is RSS-placed before any exact rule can exist (the
  ephemeral port is unknowable in advance), so any occupancy-aware
  correction *moves an established flow*. #1765 ended with that move
  adjudicated architecturally forbidden. The verdict stands until
  #9778 answers whether the move is actually unsafe under AF_XDP
  per-queue UMEM ownership, given #1748's barriered
  ownership-transfer protocol. The measurement below shows the move
  *works*; it says nothing about whether it is safe.

Two external reviewers (Codex + Antigravity) independently
reproduced the Monte-Carlo, and that half of #1649's kill stands.
The general theorem: no static placement can create the negative
dependence between flows needed to make `N ≤ M` flows avoid
occupied queues; only a reactive controller observing live
occupancy can, and that means moving established flows.

#### Re-placement measured at HEAD (#9488)

Re-placement was measured by hand, with no controller, at build
`e1cebdf8b` on `loss:xpf-userspace-fw0` (`ge-0-0-1`, 6 RX queues →
6 workers). Each run is a 70 s `iperf3 -P 12 -p 5210` push to queue
10 (`iperf-24g`, `24g exact`, so `shared_exact` with flow-fair MQFQ
on; equal-flow-enforcement not configured). A run is either
**unsteered**, or **re-pinned** at t≈14 s with one exact-5-tuple
`ethtool -N` rule per established client socket, `action <i mod 6>`
(#1748 R1's recipe). There were three runs per state, in alternating
order. Every run, with its per-worker flow counts and retransmits,
is in [`log/9488.md`](log/9488.md). Per-flow CoV is `population_cov`
(`test/incus/fairness_cov.py`) over per-stream 5 s means; Cstruct is
`xpf_fairness_cstruct` for queue 10.

| state | per-flow CoV, t45–70 (9 windows) | Cstruct | aggregate |
|---|---:|---:|---:|
| unsteered (RSS draw) | 41.5–55.4%, mean 47.2% | 0.447–0.601 | 22.05–22.74 G |
| re-pinned, `[2,2,2,2,2,2]` | 6.7–13.9%, mean 9.7% | 0.000 | 22.64–22.80 G |

How to read it:

- **Re-placement beats `Cstruct + ε`.** Every post-re-pin window
  (t45–70) sat at 6.7–13.9%, far below the unsteered runs'
  `Cstruct + 0.05` over the same windows (0.497–0.651). Aggregate did
  not change. Placement sets most of the per-flow spread at P=12 on
  this queue: in every t45–70 window, unsteered CoV sits within
  −13.9…+10.7 pp of its draw's Cstruct.
- **The re-pinned residual is larger than Gate 2's `ε = 0.05`.** It
  is 6.7–13.9 pp over a Cstruct of 0. These are 5 s windows of 1 s
  iperf3 samples, not the Gate 2 harness method, so this is not a
  Gate 2 verdict.
- **Moving all 12 flows at once costs a retransmit burst while the
  rules go in.** The 13 rules went in over about 3 s. The three runs
  saw 2681 / 2851 / 4770 retransmits in the 1 s intervals t14–16 and
  at most 3 over the rest of each run. The lowest 1 s aggregate in
  those intervals was 19.8 / 21.4 / 22.0 G, and no stream fell below
  100 Mb/s in any 1 s interval from t13 to t25.
- **#1203/#789's 49–55% CoV at P=12 is no longer the citation.** It
  was a closed-loop controller's result (PR head `979482dff`,
  2026-05-05), not a measured balanced placement. Its final comment
  attributed the number to the flow-fair MQFQ path being gated off
  for `shared_exact` and to 1024 flow buckets. The code it ran on
  already had `queue.flow_fair = queue.exact` (since `2a20cc8a0`,
  #785 Phase 3) and `COS_FLOW_FAIR_BUCKETS = 4096` (since
  `891f07525`). The MQFQ gate it cited was only in a stale doc
  comment in `types/cos.rs`, which #1210 later scrubbed. Why that
  controller stayed at 49–55% was never established.

**#1748 R1: 16.8% → 3.8%, and how to read it.** R1 used the same
re-pin recipe, run once on 2026-06-02 at master `ecdc16f2e` with
`iperf3 -i 5`. Per-flow CoV was **16.8%** on the natural draw
`[2,2,1,1,4,2]` at 16.24 G. After the re-pin it was **2.3–4.2%**
(3.8% at t55–60) on `[2,2,2,2,2,2]` at 17.5–17.8 G, with 7601
retransmits over the run. Read it as:

- **Evidence that the move works on established flows.** The HEAD
  runs above reproduce that.
- **Not a measure of the placement effect.** It was one run with no
  unsteered control, so the drop cannot be separated from run-to-run
  variance. It also ran on different code at a lower aggregate
  (16.2 G against about 22.7 G here), and its baseline sat 33 pp
  below its own draw's Cstruct (16.8% against 0.50), where no HEAD
  t45–70 window sat more than 13.9 pp below its own. Per-flow rates
  on that run were not set by per-worker share, and what did set
  them was not recorded. Its smaller delta therefore cannot size the
  placement effect at HEAD; the table above does.

### What this means operationally

- **This is primarily a per-flow distribution effect, not an
  aggregate-throughput defect.** The unevenness lives in *which
  worker* gets each flow; aggregate is evaluated against the
  existing structural cap, not assumed flat. Where the RSS draw
  leaves workers idle (`Nₐ < Nᵥ`), Gate 3's `Nₐ/Nᵥ`-scaled cap and
  the saturation detection already account for the reduced
  achievable aggregate — so idle-worker draws can lower saturated
  aggregate, and the gate does not penalize that. The favorable
  `-P 6 -p 5210` observation happened to sit near its push ceiling,
  but that is a property of that draw, not a general guarantee. The
  Cstruct-relative per-flow gate (Gate 2) handles the
  distribution side.
- **It is a transport/RSS-architecture floor, not a scheduler
  bug.** When an operator or test sees bimodal per-flow rates at
  low parallelism, the correct response is to read off the floor
  curve above, not to file a fairness regression.
- **Distinct from the mid-rate CoS rate-metering residuals**
  tracked under #1630. #1630 isolated per-class shaping floors in
  the v8 epoch rate-meter (cause-1: low-rate 100m/1g lazy-rotation
  credit loss; cause-2: a separate mid-rate ~6% residual on 3g/6g
  at low parallelism). Those are CoS scheduler-internal floors on a
  class hitting its *configured shape*; the RSS multinomial floor
  here is about how *unshaped best-effort flows distribute across
  workers*. Different mechanism, different layer — see the
  "Small-class per-class rate-metering floor (#1630 cause-1)"
  section below for the CoS-shaping floors.

## Target-service prerequisite (#8040)

**Every per-class harness in this document needs live listeners on the
VLAN-80 target that none of them can create.** Traffic runs from the LAN-side
source container, through the firewall, to `172.16.80.200`
(`IPERF_TARGET4` in `test/incus/loss-userspace-cluster.env`), which must be
running:

| ports | service | mapped by |
|---|---|---|
| 5200-5211 | per-class `iperf3 -s` | `test/incus/cos-iperf-config.set` |
| 6200-6211 | per-class TCP echo | same port -> forwarding-class grid |

Check before spending a deploy and the shared cluster lock:

```bash
./test/incus/target-services.sh status   # the whole 24-port grid, one table
./test/incus/target-services.sh check    # exit 1 if anything is down
./test/incus/target-services.sh check 5202 6200   # only the ports you need
```

`test-mouse-latency-matrix.sh`, `fairness-harness.sh` and
`cos-be-contention-harness.sh` call `check` themselves now, scoped to the
ports they use — an unrelated class being down does not block a smoke that
never sends to it, but the report on failure is always the full grid.

**Why this went unnoticed for so long.** `make test-failover` uses the DEFAULT
iperf3 port, not the per-class grid, so the standing smoke stays green at
18+ Gb/s while every harness here is unrunnable. The green everyone watches
does not cover the dependency everything else needs. On the standing loss
cluster the target is external lab hardware: it answers ICMP on
`ge-0-0-2.80` but is not an incus instance in any project and accepts no ssh,
so `target-services.sh up` can only provision a target it has a handle for and
otherwise prints exactly what must be started and where. That boundary is the
honest one — the tooling cannot invent a management path that does not exist,
but no harness should ever rediscover the fact again.

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

3. **Aggregate throughput** (declared-saturating runs only):
   The structural-throughput gate
   `observed_aggregate ≥ (Nₐ / Nᵥ) × shaper_rate × 0.95` applies
   for shaped queues **when the operator declares the offered load is
   expected to saturate the structural cap** (`fairness-eval
   --expect-saturation`). For non-shaped (best-effort) saturated
   runs: ±5% of the cluster's measured baseline for the same
   `{aᵢ}` distribution from a known-good prior run.

   **This gate is driven by the operator declaration, NOT by the
   observed `saturated` label (hb166 V-3).** Enforcing it off the
   `saturated` label alone is vacuous by construction: the label is
   `is_saturated()` over the observed aggregate, so a run that fails to
   reach the cap is simply labeled non-saturated and thereby exempted —
   no run could ever FAIL on aggregate throughput. The declaration is an
   independent input observed data cannot launder: it asserts the run
   *ought* to reach the cap, so the observed aggregate is then required
   to actually hit ≥ 95% of the `Nₐ/Nᵥ`-scaled cap for ≥ 80% of buckets.
   `--expect-saturation` requires `--shaper-rate-bps` and `--n-workers`;
   passing it with a missing/zero `--shaper-rate-bps` or `--n-workers` is
   an operator CLI mistake and fails fast with an arg-validation error
   (exit 2), not a Gate-3 FAIL (exit 1), so automation does not
   misclassify a config error as a fairness regression.
   The non-shaped "±5% of measured baseline" clause still needs a
   baseline-artifact input and is not yet implemented; the
   `--expect-saturation` shaped leg is the enforceable part today.

   When `--expect-saturation` is **not** passed: aggregate throughput is
   NOT gated (the run is treated as diagnostic on this leg regardless of
   the `saturated` label). The contract assumes such runs are cwnd-bound
   or application-bound; the test records `observed_aggregate`, the
   per-bucket `saturation_series`, and the `saturated` label for
   diagnostic context but does not apply a fail/pass on aggregate. The
   verdict field `aggregate_throughput_gate_enforced` reports whether the
   gate was active. Per-flow fairness (Gate 2), starved-flow (Gate 1),
   and mouse p99 (Gate 4) remain active for all runs.

   Rationale: a run that does not declare saturating offered load may not
   push enough load to fill the structural cap; failing it on a
   throughput floor would be a category error.

4. **Mouse p99** (only when mouse probes are present): mouse
   echo-transaction p99 latency `≤ 2 × idle_baseline`, where
   `idle_baseline` is the same probe mode against the cluster with no
   elephant traffic. The legacy `per-attempt` probe mode includes TCP
   connect latency in every sample. High-concurrency 100E100M runs use
   `persistent` mode so the gate measures established mouse request
   latency instead of the target echo daemon's accept/close capacity.
   The reducer rejects gate comparisons whose idle and loaded cells were
   captured with different probe modes or minimum-interval pacing.

   **The gate emits `VOID-NOT-ATTRIBUTABLE` when the mice and the elephants
   terminate on the SAME host (#8259), instead of PASS or FAIL.** The two
   cells being ratioed then differ by the elephants' entire offered load on
   the very machine whose service time is inside every mouse sample — ~8.6
   Gbit/s on the standing loss cluster — and the ratio attributes all of it to
   firewall queueing. `PASS` is the dangerous half rather than `FAIL`: a FAIL
   invites investigation, while a PASS gets cited as a control, and one was —
   #7159's cross-class PASS was the comparison point for #8259's FAIL and
   carries the same defect. The verdict is deliberately not a warning field
   beside a PASS/FAIL, because a warning is discarded by every consumer that
   reads `verdict`, which is how the confound survived to be cited. It exits
   2 (undetermined), never 0.

   **The second target now exists, so that void is clearable.** #8259's
   blocker was not the check but the lab: the standing target is external
   hardware with no management path, and the firewall's WAN neighbour table
   held exactly two entries — the target and the upstream router — so there
   was nowhere to move a flow to. `test/incus/mouse-target-setup.sh`
   provisions `xpf-mouse-target` at `172.16.80.201`, an incus container with
   an SR-IOV VF tagged into VLAN 80, running the same service grid
   (`target-services.sh`'s contract: iperf3 5200-5211, echo 6200-6211, plus
   port 7). `loss-userspace-cluster.env` defaults `MOUSE_TARGET_V4` to it, so
   the void check passes on the standing cluster with no per-run flag — and a
   run that deliberately wants both flows on one host, to reproduce an older
   measurement, overrides it.

   **What that does NOT do is make the earlier numbers attributable.** Every
   verdict taken before this — #7100's FAIL, #7159's PASS, and the 2x2 that
   followed — was measured with both flows on one host and stays void. They
   have to be re-taken, not reinterpreted.

   **An ABORT is distinguishable from a gate FAIL (#8244).** Every abort path
   in `test-mouse-latency-matrix.sh` used to `exit 1` and write no
   `summary.json` at all, so the only signal was an ABSENCE — and `rc=1` is
   also what a measured gate FAIL returns. On #7100 the same `rc=1` meant
   "never ran" (0 JSON files) once and "ran and failed" (62) the other time.
   Aborts now write a `summary.json` whose `verdict.verdict` is one of
   `ABORTED-LOCK-CONTENTION`, `ABORTED-TARGET-SERVICES-DOWN`,
   `ABORTED-PREFLIGHT-INVALID`, `ABORTED-PREFLIGHT-NO-PROBE` or
   `ABORTED-PREFLIGHT-FAILED`, carry the whole-grid `target_services_scan`,
   and exit 2 rather than 1. The shape matches what the reducer emits, so a
   consumer reading `summary.json["verdict"]["verdict"]` needs no change. This
   is the same defect as the void verdict above, one layer out: a state the
   harness could not measure, reported as though it had measured it.

   **The port defaults live once**, in `mouse-elephant-lib.sh`
   (`MOUSE_DEFAULT_ECHO_PORT` / `MOUSE_DEFAULT_IPERF_PORT`). They were declared
   independently in the rep script and the matrix, and `cos_port_grid_test.py`
   pinned only one of the two spellings. The echo default stays **6200**
   (queue 0 / best-effort in the canonical grid) even though that is the one
   listener currently down on the loss cluster: the echo port DETERMINES the
   forwarding class, so silently substituting an open 6201 would move the mice
   from best-effort into `iperf-100m` and change what the run measures, with
   nothing in the output saying so. The provisioning gap is reported instead —
   the abort carries the whole-grid scan, so a one-port gap reads as a one-port
   gap rather than a dead lab.

   `MOUSE_TARGET_V4` and `ELEPHANT_TARGET_V4` are separate knobs that default
   to the same address, so the check passes the moment a second host exists:
   point `ELEPHANT_TARGET_V4` at it and the gate resumes producing
   attributable numbers with no further change. There is no second host on
   VLAN 80 today, and the current target is external lab hardware with no
   management path — `test/incus/target-services.sh` records that it "is not
   an incus instance in any project, and it does not accept ssh", which is
   also why the target cannot simply be sampled instead. Artifacts predating
   the split declare no targets and are never voided on their absence: the
   void fires on positive evidence that the two are equal.

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
**runs the operator declares saturating** (`--expect-saturation`,
see Gate 3 above) — NOT to the observed `saturated` label, which is
report-only. The two regimes differ only in *expected observed_CoV*,
not in the CoV gate formula:

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

The CoV gate formula (Gate 2) does NOT change between regimes.
Saturation **labeling** (`is_saturated()` over the observed
aggregate) is for diagnostic context (operators can see "we're in
saturated regime and CoV is at the structural floor") and never by
itself changes pass/fail. Gate 3 enforcement is a separate mechanism
driven by the operator's `--expect-saturation` declaration (hb166
V-3): with that flag the observed aggregate must reach the scaled cap;
without it the aggregate leg is diagnostic. This resolves the earlier
apparent contradiction between "Gate 3 applies for saturated runs" and
"labeling does not change pass/fail" — the *label* never gates, the
*declaration* does.

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
   throughput-derived ≥1% cutoff. Since #1741 this definition holds
   with no wrap exception: the per-scan clamp sentinel-clears stamps
   that leave the window, so dead flows can no longer "ghost" back
   into the count when the u16 epoch counter wraps (~65535 ticks).
   The remaining caveats are (a) the window is elastic — the hot-path
   epoch tick is call-count-based, so its wall-clock length shrinks
   under load — and (b) flows whose packets arrive slower than the
   window (e.g. heavily shaped streams) legitimately drop out of
   `{a_i}` between packets. Consumers (#1746) get a trustworthy
   "recently-seen flows" gauge, not a session count.

   **Reducer aggregation semantics (`fairness-eval`, hb166 V-5/V-6).**
   The per-worker `{aᵢ}` is the **median** of the per-`(timestamp,
   worker)` summed active-flow count over the steady-state window. Two
   correctness rules apply. (V-6) The window is anchored to the **iperf
   run epoch** (`start.timestamp.timesecs` + warmup/final-burst), NOT to
   the scrape file's min/max timestamp — the binding/CoS TSV timestamps
   share the same epoch-seconds clock, so stale pre-run / cooldown-era
   scrapes that sit inside the file but outside the run are excluded.
   (V-5) The median **zero-fills** each worker's absent samples across
   the full in-window scrape-timestamp universe: a worker whose flows
   die partway through the window is correctly seen as inactive
   (median 0), not left "active" on the median of its live head samples.
   The CoS active-flow exporter emits rows only for live flows, so the
   reducer enforces the zero-fill; the binding exporter already zero-fills
   every worker every scrape, so for that source it is a no-op. A whole
   missing scrape (no worker on the source emitted) is not fabricated
   into spurious zeros.
5. **Computed `Cstruct`**: the structural CoV ceiling for the
   observed `{aᵢ}`.
6. **Saturation determination**: which regime the run is in (per
   the "Saturation detection" section) and the supporting
   time-series.
7. **Aggregate throughput** in Mb/s.
8. **Aggregate retransmits**: total retransmits across all senders
   (`iperf_retransmits` in `fairness-eval`). Diagnostic; not a hard
   gate.
9. **iperf CPU utilization, when present in iperf3 JSON**:
   host/remote totals plus the derived sender-side total/user/system
   percentages from iperf3's `cpu_utilization_percent`. Diagnostic;
   not a hard gate, but needed to separate dataplane unfairness from
   sender or receiver saturation. Absence of these optional fields means
   missing diagnostic context, not proof that CPU was healthy.
10. **ECN marks/drops** (if AQM is enabled): total CE marks and
   AQM drops. Diagnostic for future Path 2 v2 work.
11. **Mouse p99 latency** (when mouse probes are present).
12. **Steady-state window**: explicit start/end timestamps,
    excluding the first 5 seconds (warmup) and any final
    sender-shutdown bursts. `fairness-eval` emits these as
    `steady_state_window` (iperf-epoch and run-relative start/end) and
    (hb166 V-7) rejects a run whose OBSERVED non-omitted 1-second bucket
    count falls below the 60 s minimum — the check is on measured
    samples, not the self-reported iperf duration, so a truncated JSON
    that merely *declares* a long run is rejected with an explicit error
    rather than producing a CoV from a handful of buckets. iperf `-O`
    omitted intervals are filtered out of the steady-state window.

The `fairness-eval` verdict always includes the doc-mandated required
metrics (hb166 V-9): `per_flow_throughput_mbps` (item 1: `stream_count`
plus `min/p25/median/p75/max_mbps`, computed over the FULL iperf stream
set — a starved / zero-throughput stream is counted as 0 Mb/s, not
dropped, so a failing run's per-flow distribution surfaces the starved
flow instead of undercounting it), `steady_state_window` (item 12:
`iperf_epoch_start/end`, `relative_start/end_sec`), and
`saturation_series` (item 6: the per-bucket `aggregate_buckets_bps`
series, the `structural_cap_bps` it is judged against, and
`saturated_bucket_fraction`). It also always includes `iperf_retransmits`
and `iperf_reverse`. When iperf3 exports `end.cpu_utilization_percent`, the
verdict also includes `iperf_cpu_host_total_percent`,
`iperf_cpu_host_user_percent`, `iperf_cpu_host_system_percent`,
`iperf_cpu_remote_total_percent`, `iperf_cpu_remote_user_percent`,
`iperf_cpu_remote_system_percent`, `iperf_sender_cpu_total_percent`,
`iperf_sender_cpu_user_percent`, and
`iperf_sender_cpu_system_percent`. In reverse mode, the sender-derived
fields map to the remote iperf endpoint; in forward mode, they map to
the host endpoint.

Mixed-workload CoS validation MUST run at least two classes
concurrently under one metrics scrape so class-specific `{a_i}` cannot
silently collapse back to the per-binding aggregate. The canonical
harness command is:

```bash
COS_IFINDEX=<egress-ifindex> ./test/incus/fairness-harness.sh --mixed-cos
```

With the default symmetric CoS fixture this runs port 5202
(`iperf-1g`, queue 2) and port 5205 (`iperf-9g`, queue 5) concurrently,
then invokes `fairness-eval` twice against the same
`xpf_userspace_cos_active_flow_count` scrape: once for queue 2 and
once for queue 5. Non-canonical fixtures must set `COS_QUEUE_ID` and
`MIXED_COS_QUEUE_ID` explicitly. `MIXED_RSS_EXPECTATION` defaults to
`RSS_EXPECTATION`, so one expectation gate applies to both classes
unless the operator explicitly sets `MIXED_RSS_EXPECTATION=any` or a
different mixed-class expression.

For hostile qualification runs where generator placement itself is a
suspect, use the opt-in isolated mode:

```bash
COS_IFINDEX=<egress-ifindex> \
IPERF_CPUSET=0-3 MIXED_IPERF_CPUSET=4-7 \
IPERF_NETWORK_ID=vf0-rss-a MIXED_IPERF_NETWORK_ID=vf1-rss-b \
ARTIFACT_DIR=/tmp/fairness-isolated \
./test/incus/fairness-harness.sh --mixed-cos-isolated
```

`--mixed-cos-isolated` still evaluates both classes from one metrics
scrape, but it requires both compute isolation and explicit network/RSS
isolation. Compute isolation is enforced by parsing
`IPERF_CPUSET` / `MIXED_IPERF_CPUSET` as CPU bitmaps and rejecting any
overlap. Network isolation is enforced by distinct generator netns
values or distinct `IPERF_NETWORK_ID` / `MIXED_IPERF_NETWORK_ID`
domains. `PRIMARY_RSS_STEERING` and `MIXED_RSS_STEERING` are free-form
audit notes only; they are never accepted as proof of isolation.

CPU-set validation rejects CPU IDs above the local host's discovered
CPU topology (`/sys/devices/system/cpu/possible`, then `nproc --all`).
If the topology cannot be discovered, the harness fails before expanding
CPU ranges; set `CPUSET_MAX_CPU_ID=<max-cpu-id>` explicitly in that
environment. When the generator runs on a remote host with a different
CPU topology, set `CPUSET_MAX_CPU_ID=<max-remote-cpu-id>` explicitly. A
hard safety ceiling of `CPUSET_HARD_MAX_CPU_ID=8191` prevents typo
ranges from expanding indefinitely; raise it only for deliberately
larger systems.

For remote generators, use numbered argv variables instead of a shell
prefix string. Launcher args run on the local host before entering the
generator context; generator args run after the launcher and before
`iperf3`. Numbered argv variables must be contiguous from `_0`; a gap
such as `IPERF_LAUNCH_ARG_0` plus `IPERF_LAUNCH_ARG_2` is rejected
instead of silently dropping the later argument. Indices must use
canonical decimal spelling (`_0`, `_1`, `_2`); leading-zero forms such
as `_01` and values outside the shell arithmetic range are rejected.

```bash
COS_IFINDEX=5 \
IPERF_CPUSET=0-3 MIXED_IPERF_CPUSET=4-7 \
IPERF_NETWORK_ID=lan-vf-rss-a MIXED_IPERF_NETWORK_ID=lan-vf-rss-b \
IPERF_LAUNCH_ARG_0=/usr/bin/incus \
IPERF_LAUNCH_ARG_1=exec \
IPERF_LAUNCH_ARG_2=loss:cluster-userspace-host \
IPERF_LAUNCH_ARG_3=-- \
MIXED_IPERF_LAUNCH_ARG_0=/usr/bin/incus \
MIXED_IPERF_LAUNCH_ARG_1=exec \
MIXED_IPERF_LAUNCH_ARG_2=loss:cluster-userspace-host \
MIXED_IPERF_LAUNCH_ARG_3=-- \
ARTIFACT_DIR=/tmp/fairness-isolated \
./test/incus/fairness-harness.sh --mixed-cos-isolated
```

The placement file records per-class ports, streams, reverse flag, CoS
ifindex/queue, shaper rates, launcher args, generator CPU sets, network
domains, generator netns, generator args, binaries, RSS/NIC steering
notes, and the exact command intent. It also appends best-effort local
launcher PID/affinity data; generator-context proof must come from the
launch target or wrapper because remote launchers such as `incus exec`
do not expose the remote iperf PID to this local script. The
lightweight `--mixed-cos` mode remains the default for routine runs.

Single-class CoS validation MUST NOT stop at the low-rate fixture
classes. The 100M and 1G classes are mostly shaper-dominated and can
produce very low CoV even when high-rate classes remain unfair. Use the
class sweep harness to exercise every canonical fixture port:

The canonical iperf CoS fixtures intentionally give the two low-rate
exact classes deeper buffers than the implicit admission/buffer cap:
`scheduler-100m` uses `buffer-size 500k` and `scheduler-1g` uses
`buffer-size 4m`. Without explicit `buffer-size`, queue `base` is
`max(transmit_rate_bytes/100, 96_000)` (10 ms of bytes with a 96 KB
floor), then admission applies the flow-aware
`prospective_active * 24 KB` expansion plus the #717 5 ms envelope clamp
(`.min(delay_cap.max(base))`). For an UNSHAPED flow-fair queue
(`transmit_rate_bytes == 0`, i.e. no per-queue shaper) the delay cap is
anchored to a physical link-rate floor
(`COS_FLOW_FAIR_UNSHAPED_DRAIN_RATE_BYTES`, 10 Gb/s) rather than the
literal 0 rate — an unshaped queue drains at line rate, not zero. Before
hb166 T-5 the rate-0 `delay_cap` computed 0, so `.min(delay_cap.max(base))`
pinned the aggregate cap at `base` regardless of flow count: the
flow-aware expansion collapsed and a new flow's first packet was dropped
at the aggregate cap (the rate-0 twin of the #704/#707 regression). #1312
showed that those implicit caps
reproduce reverse-mode tail-drop under `-P 12` even when equal-flow
suppression is disabled: the 100M class hit aggregate admission drops,
and the 1G class hit per-flow share drops. The fixture overrides
therefore trade queue residence for retransmit suppression (q1
500k@100M ≈ 40 ms, q2 4m@1G
≈ 32 ms at full queue). Do not remove or shrink these buffers without
rerunning at least the q1/q2 reverse sweep and checking retransmits plus
CoS admission drop deltas.

Those values are an explicit validation-fixture tradeoff, not a general
low-latency recommendation. The extra headroom stabilizes the `-P 12`
reverse fairness workload, but it can add bufferbloat for
latency-sensitive traffic. Production configs that care about tail
latency should size these buffers from the service SLO rather than
copying the validation fixture blindly.

Schedulers can also express `buffer-size` as a percent. Userspace does
not treat that as a byte value of zero: the Go snapshot carries
`buffer_size_percent`, and the Rust CoS builder resolves it to bytes as a
percentage of the interface CoS burst pool before queue admission and
token-bucket runtime state are built. For the fairness fixtures above,
the explicit byte sizes remain intentional so the queue residence tradeoff
is visible in the config. Percent buffers are validated per interface
unit: scheduler-map entries bound to the same unit cannot total more than
100% of that unit's CoS burst pool. xpf rejects the Junos-accepted `0%`
form because the additive userspace protocol uses zero as the absent
field value and the runtime still applies a minimum queue burst floor.

```bash
COS_IFINDEX=<egress-ifindex> \
IPERF_LAUNCH_ARG_0=/usr/bin/incus \
IPERF_LAUNCH_ARG_1=exec \
IPERF_LAUNCH_ARG_2=loss:cluster-userspace-host \
IPERF_LAUNCH_ARG_3=-- \
./test/incus/fairness-cos-class-sweep.sh
```

The sweep runs ports 5200..5211 through `fairness_multi_sample.py`,
preserves per-class artifacts, writes `summary.tsv` and `summary.md`,
and returns non-zero after completing all classes if any class misses
the Cstruct-aware multi-sample contract (`mean_gap ≤ 0.05` and
`max_gap ≤ 0.05` by default). The summary still reports mean/max/stdev
observed CoV for context, but absolute CoV is not the default pass/fail
gate; use the wrapper's opt-in `--max-*cov` flags only for deliberately
balanced-RSS fixtures.

For throughput-headroom investigations, narrow the sweep to the high-rate
classes and preserve the raw iperf/flow artifacts from each sample:

```bash
COS_IFINDEX=<egress-ifindex> \
REVERSE= \
METRICS_URL=http://127.0.0.1:8080/metrics \
./test/incus/fairness-cos-throughput-headroom.sh
```

By default this wrapper runs `CLASS_FILTER=q8,q9,q10` under the strict
exact fixture, then applies a diagnostic `surplus-sharing` fixture and
runs the same class set again before restoring the strict fixture. The
surplus-sharing leg is a headroom diagnostic, not the product fairness
contract: it shows whether the dataplane can recover aggregate throughput
when exact queues are allowed to borrow root surplus. Each harness sample
now preserves `iperf-single.json` (or `iperf-primary.json` /
`iperf-mixed.json`) plus `binding-flows.tsv` and `cos-flows.tsv` under
the sample artifact directory, so per-stream rates and active-flow
placement can be audited after the wrapper exits. The class sweep passes
`--sample-cooldown-sec` to the multi-sample wrapper (`10` seconds by
default) so back-to-back iperf runs do not reuse stale CoS active-flow
buckets as current-run RSS evidence.

## 100E100M and surplus give-back validation

Issue #1321 adds two deployment-facing validation contracts on top of the
Cstruct-relative fairness gate:

1. **100E100M**: 100 elephant streams must keep useful aggregate
   throughput while 100 mouse probes keep bounded tail latency and do not
   starve.
2. **Work-conserving surplus give-back**: a surplus-sharing borrower may
   exceed its guarantee while peers are idle, but it must hand back that
   surplus quickly when a peer demands its guarantee and reclaim it after
   the peer goes idle.

These are separate from equal-flow enforcement. Equal-flow enforcement is
a non-work-conserving comparison mode for raw equality vs throughput loss;
it is not proof that surplus-sharing is fair.

The mouse-latency matrix reducer now accepts a configurable gate cell, so
the same artifact format can express both the legacy #905 gate and the
#1321 100E100M gate. The canonical 100E100M reduced run is:

```bash
MOUSE_LATENCY_CELLS=$'0 100\n100 100' \
MOUSE_LATENCY_GATE_ELEPHANTS=100 \
MOUSE_LATENCY_GATE_MICE=100 \
MOUSE_LATENCY_GATE_PERCENTILE=p999_us \
MOUSE_PROBE_CONNECTION_MODE=persistent \
MOUSE_PROBE_MIN_INTERVAL_MS=20 \
./test/incus/test-mouse-latency-matrix.sh /tmp/xpf-100e100m-exact
```

Run it once under the strict exact fixture and once after applying the
surplus-sharing fixture. Use `MOUSE_COS_SURPLUS_SHARING=1` for the
surplus leg; the per-rep harness re-applies CoS on every preflight/rep,
so a one-time manual `apply-cos-config.sh --surplus-sharing` before the
matrix is not sufficient. 100E100M uses persistent probe connections with
a 20 ms per-coroutine interval because the validation target is tail
latency of mouse transactions under elephant load, not the echo server's
ability to accept and close tens of thousands of short TCP sessions or
serve millions of unpaced echo requests per minute. A 60-second, 100-mouse
rep still produces roughly 280k samples on the isolated validation
cluster. The reducer writes
`summary.json` with the gate verdict, idle and loaded tail latency,
ratio, selected percentile, and per-cell representative probe. Probe
artifacts now include `rtt_us.p999`; the reducer carries that forward as
`median_rep.p999_us`. The 100E100M qualification should gate p99.9 by
setting `MOUSE_LATENCY_GATE_PERCENTILE=p999_us`; legacy #905-style runs
may keep the default p99 gate. When a non-p99 gate is selected, the
representative rep is also selected by that same percentile. For p99
runs, `summary.json` keeps the historical `p99_idle_us` /
`p99_loaded_us` aliases alongside the generic `idle_us` / `loaded_us`
fields. The reducer also verifies that gate cells share the same
`MOUSE_PROBE_CONNECTION_MODE` and `MOUSE_PROBE_MIN_INTERVAL_MS` provenance;
mixed per-attempt/persistent or paced/unpaced gate artifacts are reported
as insufficient data rather than a PASS/FAIL verdict.

When the settle snapshot pull succeeds and diagnostics run, high-rate
100E100M reps include settle evidence before the mouse probe.
`cwnd-settle.json` records the final settle-window aggregate, threshold
reasons, min/median/max of per-flow mean throughput, retransmits, and
latest cwnd distribution. `mpstat-settle.txt`
captures source-side CPU during the settle window.

Every load generator and sampler the rep script backgrounds runs on the
source container through `incus exec`, and each is stopped **on the
container**, not by killing the local client (#7159, #8270). Killing a
backgrounded `incus exec` client does not terminate the remote command —
incus leaves it running when a non-interactive client disconnects — so
before this the elephant and both mpstat samplers outlived any rep that
exited early. For the elephant that corrupted the measurement rather
than merely leaking: it kept sending for the rest of its 90 s budget
while the next rep started ~8 s later, so the next rep's elephants
shared the shaped class with the previous rep's, missed the cwnd-settle
floor, exited early themselves, and orphaned another. One marginal
rejection took the whole cell to zero valid reps with a plausible
`cwnd-not-settled` reason. `test/incus/mouse-elephant-lib.sh` gives each
remote job a pidfile (`echo $$ > <pidfile>; exec <cmd>`, both halves
load-bearing) and stops it by that pid after confirming
`/proc/<pid>/cmdline` still names the expected program, so a reused pid
is spared. `make test-mouse-elephant-lib` self-tests it hermetically.
A rep also refuses to start when an iperf3 client is already running on
the source container (`INVALID-stale-elephant-client`), so a stranger
sharing the class is a named invalidation instead of a halved rate. `manifest.json` records
`settle_budget_s`, `cwnd_settle_elapsed_s`, and tri-state
`cwnd_settle_ok`: `true` only after a successful settle diagnostic,
`false` after an evaluated-but-unsettled diagnostic, and `null` for cells
that did not run the settle gate (`N=0`, pull failure, or other pre-gate
invalidations). Use `MOUSE_LATENCY_SETTLE_BUDGET=<seconds>` for a
deliberately longer high-rate settle budget. Probe artifacts also carry `phase_us` and
`coroutines` diagnostics so a degenerate-coroutine failure can be read as
timer wake delay (`start_gap_us` / `sleep_overshoot_us`), client socket
backpressure (`drain_us`), or echo-path delay (`read_us`) before blaming
root surplus arbitration or dataplane queue residence. The per-rep
`cos-interface-pre.txt`, `cos-interface-settle.txt`, and
`cos-interface-post.txt` snapshots preserve the CoS queue counters needed
for that cross-check.

#### Env-shape consistency guard (#1365)

`SHAPER_BPS` MUST move with `ELEPHANT_PORT`: the cwnd-settle gate
requires the elephant aggregate to reach `0.7 * SHAPER_BPS`, but the
forwarding class implied by `ELEPHANT_PORT` (per
`test/incus/cos-iperf-config.set`) can only ever deliver up to its
configured cap — the scheduler `transmit-rate` for `exact` classes, or
the interface `shaping-rate` for the non-exact best-effort / uncapped
classes. When the settle floor exceeds that cap the gate is
*arithmetically unsatisfiable*: every loaded rep INVALIDates with
`cwnd-not-settled` before the mouse probe ever starts, regardless of
dataplane or scheduler health. That is the #1365 footgun — the matrix
was run with `ELEPHANT_PORT=5202` (the 1 Gbps `iperf-1g` exact class)
paired with `SHAPER_BPS=10000000000`, so the 7 Gbps floor could never
be met against a 1 Gbps cap and the cell reported `INSUFFICIENT-DATA`.

`test-mouse-latency.sh` now runs a static consistency guard before each
rep:
`mouse_latency_orchestrate.py check-env-consistency <port> <shaper_bps>`.
It parses the applied CoS fixture as its single source of truth (so the
table cannot drift from the fixture) and `ABORT`s with an actionable
message — naming the class, its cap, the computed floor, and a hint to
either set `SHAPER_BPS` to the class cap or pick a port whose class cap
is `>= floor` — instead of burning a whole matrix cell on an impossible
pairing. A classified port whose forwarding-class has no scheduler-map
entry is treated as a hard fixture error (not silently defaulted to the
interface shaper), keeping the table honest. The floor is computed with
ceiling rounding (`ceil(0.7 * SHAPER_BPS)`) so the guard never
under-reports it: the real gate compares the aggregate against the float
threshold `0.7 * SHAPER_BPS`, and a borderline pairing whose threshold
sits just above the integer cap is correctly rejected rather than passed
by truncation. To exercise a genuinely high-rate class, point at a high-rate
port with the matching bps, e.g. `ELEPHANT_PORT=5205 SHAPER_BPS=9000000000`
(the 9 Gbps `iperf-9g` exact class). The guard is purely static (no
cluster contact) and is covered by `mouse_latency_orchestrate_test.py`
(`parse_cos_class_caps` / `check_settle_threshold_satisfiable`),
including a drift guard that cross-checks the parsed table against the
canonical port→rate map.

```bash
MOUSE_COS_SURPLUS_SHARING=1 \
MOUSE_LATENCY_CELLS=$'0 100\n100 100' \
MOUSE_LATENCY_GATE_ELEPHANTS=100 \
MOUSE_LATENCY_GATE_MICE=100 \
MOUSE_LATENCY_GATE_PERCENTILE=p999_us \
./test/incus/test-mouse-latency-matrix.sh /tmp/xpf-100e100m-surplus
```

#### Measured verdict: surplus-sharing is incompatible with the 100E100M p99.9 contract

**Do not ship the surplus fixture as a latency-bearing configuration.** It is a
headroom diagnostic, and under the 100E100M contract it costs three orders of
magnitude of mouse tail latency. Measured on `loss:xpf-userspace-fw0/fw1` at
master `d8a876042` (2026-09-02), both legs in one session on a harness with the
#8268/#8270 orphan defect fixed, and with the **surplus leg run first** so the
result cannot be an artifact of elapsed session time:

| | strict exact | surplus |
|---|---|---|
| gate verdict | **PASS**, ratio 1.19 | **INSUFFICIENT-DATA**, 0 of 15 reps valid |
| idle p99.9 | 6 781 us | 6 662 us |
| loaded p99.9 | 8 085 us (10/10 valid) | 740-1 349 **ms** (10 reps with probe data) |
| implied loaded/idle | 1.19 | **111x - 202x** |
| elephant settle | 950-959 Mb/s, util 0.944-0.951 | 977-1 117 Mb/s, util 0.907-1.060 |
| mouse attempts, min vs median | 2 822 vs 2 871 | **53-206** vs ~2 885 |

The tail is **path-side, not client-side**, by the phase decomposition
(attribution rule fixed before the run): `sleep_overshoot_us` p99.9 is 3.3-3.9
ms under exact and 3.1-3.6 ms under surplus, `drain_us` p99.9 is 49-54 us and
53-69 us — comparable — while `read_us` p99.9, the echo path, carries the whole
difference. Both legs settle their elephants above the shape on every rep, so
this is not an unsettled or collapsed cell.

The starvation is **concentrated, not uniform**: 10-15 of 100 mouse coroutines
run at roughly 300 ms per transaction for the whole rep while 50-75 of their
peers on the same best-effort class run at ~0.8 ms. The strict-exact control is
uniform to within 2%.

##### What the counters say about where it happens

Loaded-cell deltas on `xpf_userspace_cos_queue_token_starvation_parks_total`
for the elephant queue (`queue_id=2`), same procedure, same node, adjacent in
time:

| leg | delta over the loaded cell |
|---|---|
| strict exact | **+17 573 417** |
| surplus | **0** |

Under strict exact the queue parks at the shaper continuously; under surplus it
never parks at all, because it is borrowing instead. Per-rep
`show class-of-service interface` at the settle point agrees and localises it
further (surplus vs exact, same rep index):

| `queue_id=2` | surplus | strict exact |
|---|---|---|
| bytes served as guarantee / surplus | 178 M / **2 756 M** | 2 624 M / **0** |
| sojourn ewma / peak | 8.0 ms / 90.2 ms | **29.2 ms / 250.9 ms** |
| `flow_share` drops | 14 225 | 4 167 |
| drain invocations | **1 821 857** | 93 929 |
| waterfill `eligible_visits` -> `phase1_admit` | 3 668 362 -> **6 402** | 508 030 -> 93 929 |

Two things follow, and the first is the one that keeps surprising people:

1. **The mouse queue never queues, in either leg.** `queue_id=0` is identical
   across the fixtures — 0 packets queued, 0 parked, `park_root=0`,
   `park_queue=0`, no sojourn line. So the mouse tail is **not** CoS queue
   residence. This reproduces the load-bearing negative result from 2026-06-10
   (`docs/pr/1829-p2/evidence.md`) at a new head, and it is why looking for the
   tail in queue-depth telemetry finds nothing.
2. **Standing queue correlates with PASSING.** The elephant sojourn is *higher*
   in the leg that passes (29.2 ms ewma against 8.0 ms). The correlation is
   inverted, exactly as #1829 Phase 2 recorded.

What the surplus leg does instead of queueing is spin: 7x the eligibility
visits for 14x fewer admissions, and 19x the drain invocations, on the same
owner worker. That is where the service delay is being spent.

##### What this does NOT establish

Why a *minority* of mouse flows is affected rather than the whole class. The
tier sizes are near multiples of 100/6 and the mlx5 VF exposes 6 combined RX
queues to 6 workers, which makes a per-worker effect the obvious hypothesis —
but the artifacts carry no flow-to-worker mapping, so this measurement cannot
choose between a per-worker arbitration effect and a whole-class effect that
happens to spare most flows. Two surplus reps also tripped
`error_rate >= 0.01` (0.0306 and 0.0337, 5 524 errors in one), which has not
been seen in a strict-exact leg and is unexplained.

##### The gate cannot say any of this itself

Every surplus loaded rep above was rejected `degenerate-coroutine`, so the
reducer reported `INSUFFICIENT-DATA` rather than FAIL for a cell whose tail was
two orders of magnitude over the threshold. That is a defect in the apparatus,
tracked separately as #8277: the rule is a fairness predicate used as a
validity predicate, so a *concentrated* tail invalidates the rep that
demonstrates it. A *uniform* slowdown would still FAIL correctly. Until that is
fixed, an `INSUFFICIENT-DATA` verdict on this fixture must be read as a
candidate masked FAIL and the per-rep `probe.json` read directly.

Surplus give-back uses a reduced phase artifact instead of trying to
infer phase semantics from unrelated per-class sweeps. The validator is:

```bash
./test/incus/fairness_surplus_giveback_validate.py \
  --input /tmp/xpf-surplus-giveback/phases.json \
  --out /tmp/xpf-surplus-giveback/verdict.json
```

The input artifact must contain `root_cap_mbps`,
`borrower_guarantee_mbps`, `peer_guarantee_mbps`,
`handback_samples`, and four named
phases: `borrow_alone`, `peer_demand`, `peer_steady`, and
`peer_idle_reclaim`. Each phase records `throughput_mbps.borrower` and
`throughput_mbps.peer`; `peer_steady` may also record
`cos_admission_drops.peer`. Handback evidence must be time-domain
throughput samples in `handback_samples`. Scalar
`handback_window_sec` values and self-attested handback labels are not
accepted as substitutes because the validator must derive the handback
point from auditable data.

**Handback series cross-checks (#4239 V-8).** A single already-settled
snapshot cannot prove a give-back transition — its self-attested `t_sec`
would be the only evidence, and a one-element artifact trivially clears
the ≤5 s gate. The validator therefore requires the `handback_samples`
series to demonstrate an OBSERVED transition:

- at least `--min-handback-samples` samples (default 2);
- strictly increasing `t_sec` (an ordered time series);
- consecutive gaps within `--max-handback-sample-gap-sec` (default 5 s),
  so the derived handback time is bounded rather than hidden inside a
  wide blind gap;
- a pre-handback baseline sample (peer guarantee not yet restored)
  BEFORE the first post-handback sample.

The derived handback time is the first post-handback sample that follows
a pre-handback one, so the accepted `t_sec` is bracketed by the observed
transition. The timestamps themselves are still generator-supplied; the
ordered-series cross-check is the auditability bound available in a
reduced artifact, and an independent wall-clock derivation belongs in the
live reducer.

**No live runner yet (#4239 V-8).** Nothing in the tree produces
`phases.json`; the 100E100M give-back contract is exercised only by
hand-built artifacts today, so this validator is a MANUAL gate. The
structural cross-checks above are what keep a hand-built artifact honest
until a live reducer (iperf interval JSON + Prometheus/dataplane status
→ `phases.json` + `handback_samples` with wall-clock `t_sec`) is built.

The default gates are:

- borrower-alone throughput exceeds 105% of the borrower guarantee
- peer-demand throughput is non-zero (at least 1% of the peer guarantee)
  as a liveness proxy; this phase proves the artifact is not decorative,
  while `peer_steady` and handback evidence enforce actual guarantee
  service
- peer steady throughput reaches at least 95% of its guarantee
- handback window is at most 5 seconds
- borrower throughput during peer steady demand falls to at most 90% of
  borrower-alone throughput
- borrower reclaim throughput is at least 110% of its peer-steady
  throughput
- borrower reclaim throughput reaches at least 90% of borrow-alone
  throughput
- root cap is not exceeded by more than 2%
- peer steady CoS admission drops are zero by default

The phase artifact is the handoff between live traffic runners and the
contract gate. A live runner can populate it from iperf JSON, Prometheus,
or dataplane status snapshots, but the pass/fail semantics are
centralized in the reducer so future harness changes do not silently
drift the contract.

For the symmetric reverse fixture on the loss cluster, `COS_IFINDEX=5`
selects the `ge-0-0-1` egress. For forward-path sweeps, do not hardcode
the RETH unit's displayed name into the harness; use the ifindex emitted
by `xpf_userspace_cos_active_flow_count` for the actual shaped egress in
that run. `METRICS_URL` must be reachable from the harness host. If the
dataplane only exposes Prometheus on the firewall VM loopback, expose a
temporary host-local proxy or run the harness in a context that can reach
that endpoint; an unreachable metrics URL is an environment error, not a
fairness result.

## Required metrics — exported in production via gRPC/Prometheus

For production observability, xpf MUST export:

- **`xpf_fairness_active_flows{ifindex=..., queue_id=...}`** gauge:
  total active flows observed for the egress CoS queue in the current
  userspace status snapshot.
- **`xpf_fairness_active_workers{ifindex=..., queue_id=...}`** gauge:
  workers with at least one active flow for the egress CoS queue.
- **`xpf_fairness_max_worker_flow_share{ifindex=..., queue_id=...}`**
  gauge: largest fraction of the queue's active flows owned by one
  worker. This is the production-facing `max-worker-flow-share`
  signal from #1247.
- **`xpf_fairness_cstruct{ifindex=..., queue_id=...}`** gauge: the
  current computed structural CoV ceiling for the egress CoS queue.
  It is derived from
  `xpf_userspace_cos_active_flow_count{ifindex,queue_id,worker_id}`;
  no packet-path state or global atomics are added.
- **`xpf_fairness_cos_active_flow_counts_truncated`** gauge: 1 when
  the status snapshot was truncated before the fairness RSS gauges
  were derived; 0 otherwise.
- **`xpf_fairness_rss_expectation_configured{ifindex=..., queue_id=..., kind=...}`**
  gauge: 1 for each configured opt-in RSS/workload expectation. The
  label is the stable expectation kind, not the full threshold string.
- **`xpf_fairness_rss_expectation_value{ifindex=..., queue_id=..., kind=...}`**
  gauge: configured numeric value for expectation kinds that take a
  value, such as active-worker count or `max-worker-flow-share`
  threshold.
- **`xpf_fairness_rss_skew_violation{ifindex=..., queue_id=..., kind=...}`**
  gauge: 1 when the configured RSS/workload expectation fails for the
  egress CoS queue; 0 when it passes. It is ABSENT while the expectation
  is indeterminate (#9369).
- **`xpf_fairness_rss_expectation_indeterminate{ifindex=..., queue_id=..., kind=...}`**
  gauge: 1 when the expectation cannot be judged because the CoS
  active-flow snapshot was truncated; 0 otherwise. A truncated snapshot
  keeps only a prefix of the sorted `(ifindex, queue, worker)` rows, and a
  verdict computed from that prefix can be a false PASS or a false FAIL. So
  every constrained kind is withheld rather than guessed; `any` still
  evaluates. `show chassis cluster data-plane fairness` prints the same
  verdict as `INDETERMINATE` in the `Result` column.
- **`xpf_fairness_saturated{ifindex=..., queue_id=...}`** Prometheus gauge: 0 or
  1. Computed from the daemon's rolling 30-second per-flow byte
  window as aggregate queue throughput vs the configured CoS queue
  transmit rate (per "Saturation detection"). If a queue does not
  report an explicit `transmit_rate_bytes`, the daemon falls back to
  the interface shaping rate; on a multi-queue interface this means
  `saturated=1` requires that queue to approach the interface-level
  cap.
  Diagnostic only — saturation does not change pass/fail of the
  Cstruct gate, but operators may want to know whether their
  workload is actually hitting the shaper. The original v3 enum
  with `{non_saturated, saturated_balanced, saturated_skewed,
  low_n_degenerate}` labels is dropped: with the structural-
  ceiling gate replacing fixed regime bands, distinguishing
  balanced/skewed/degenerate is not load-bearing on pass/fail —
  the per-worker active-flow distribution `{a_i}` is the underlying
  signal and is exported separately if the harness needs it for
  context.
- **`xpf_fairness_observed_cov{ifindex=..., queue_id=...}`** gauge: rolling
  observed CoV across per-flow byte totals for the queue.
- **`xpf_fairness_starved_flows{ifindex=..., queue_id=...}`** counter:
  monotonic count of flows that enter the starved-flow threshold
  (< 1% of mean per-flow throughput), de-duplicated while the flow
  remains in the rolling window.
- **`xpf_fairness_equal_flow_estimate_valid{ifindex=..., queue_id=...}`**
  gauge: 1 when the measurement-only equal-flow suppression estimator
  has enough untruncated source data to model this queue. A valid
  estimate requires an untruncated flow-worker byte source, an
  untruncated CoS active-flow source, and at least two active workers
  with non-zero rolling byte samples.
- **`xpf_fairness_equal_flow_sampled_active_workers{ifindex=..., queue_id=...}`**
  gauge: active workers that also have non-zero rolling byte samples in
  the estimator window.
- **`xpf_fairness_equal_flow_unsampled_active_workers{ifindex=..., queue_id=...}`**
  gauge: workers with active flows in the CoS snapshot but no rolling
  byte samples in the estimator window. Non-zero here means the
  equal-flow estimate is using a partial traffic sample.
- **`xpf_fairness_equal_flow_target_per_flow_bps{ifindex=..., queue_id=...}`**
  gauge: the slowest sampled active worker's observed per-flow bit rate.
  This is the strict equal-flow target a non-work-conserving suppressor
  would use if it chose to trade aggregate throughput for
  lower absolute per-flow spread.
- **`xpf_fairness_equal_flow_observed_bps{ifindex=..., queue_id=...}`**,
  **`xpf_fairness_equal_flow_capped_bps{ifindex=..., queue_id=...}`**,
  **`xpf_fairness_equal_flow_suppressed_bps{ifindex=..., queue_id=...}`**,
  and
  **`xpf_fairness_equal_flow_throughput_loss_ratio{ifindex=..., queue_id=...}`**
  gauges: measurement-only aggregate model of current throughput,
  throughput after strict equal-flow suppression, withheld throughput,
  and withheld/current ratio. These metrics do **not** feed the
  scheduler and do **not** change the Cstruct pass/fail contract.
- **`xpf_fairness_equal_flow_worker_observed_bps{ifindex=..., queue_id=..., worker_id=...}`**,
  **`xpf_fairness_equal_flow_worker_observed_per_flow_bps{ifindex=..., queue_id=..., worker_id=...}`**,
  **`xpf_fairness_equal_flow_worker_cap_bps{ifindex=..., queue_id=..., worker_id=...}`**,
  and
  **`xpf_fairness_equal_flow_worker_suppressed_bps{ifindex=..., queue_id=..., worker_id=...}`**
  gauges: per-worker breakdown of the same hypothetical cap. These are
  intended to answer "which worker would we slow, by how much?" without
  depending on whether an opt-in enforcement mode is configured.
- **`xpf_userspace_cos_flow_fair_buckets_occupied{ifindex=..., queue_id=...}`**
  and **`xpf_userspace_cos_flow_fair_flows_active{ifindex=..., queue_id=...}`**
  gauges (#1830 (g)): bucket-vs-flow occupancy for distinguishing SFQ
  hash-collision unfairness from demand unfairness. `buckets_occupied`
  is the instantaneous count of backlogged flow-fair SFQ buckets summed
  across workers; `flows_active` is the flow-cache active-window
  (~650 ms) distinct-flow count mapped to the queue, summed across
  workers (it equals `sum by (ifindex, queue_id)` of
  `xpf_userspace_cos_active_flow_count`). The ratio is meaningful only
  while the queue is CONTINUOUSLY backlogged (sustained `iperf3 -P N`):
  there, `buckets_occupied` persistently below the known concurrent
  flow fan-in (equivalently `flows_active / buckets_occupied`
  persistently above 1) indicates hash collisions shrinking per-flow
  shares. On idle or bursty queues `flows_active` naturally exceeds
  `buckets_occupied` — demand variance, not collision evidence.

When `class-of-service schedulers <name> equal-flow-enforcement` is
enabled on a positive exact-rate scheduler without `surplus-sharing`, the
Rust shared-v8 CoS lease exports actual enforcement telemetry through
`xpf_userspace_cos_equal_flow_*` metrics. These are intentionally
separate from the measurement-only estimator above: the estimator models
the observed traffic window, while the Rust metrics report whether the
current lease epoch is configured, enforced, capped, suppressed, or
failed open with a bounded reason. Acquire-side stale/tag mismatches
are exported as a separate monotonic counter, not by rewriting the
current epoch reason, so a stale worker cannot clobber the
rotation-published payload.

The per-flow target the publisher enforces is policy-selectable
(#1746): `equal-flow-target-policy (slowest | mean | ideal-share)` on
the scheduler, defaulting to the byte-unchanged clip-to-slowest `min`
reduction. `mean` clips toward the aggregate-weighted mean achieved
per-flow rate; `ideal-share` is the literal nominal share (a documented
no-op in capacity-limited regimes). The active policy is exported as
the sibling info metric
`xpf_userspace_cos_equal_flow_target_policy{ifindex,queue_id,policy}`
(a new series — the existing `xpf_userspace_cos_equal_flow_*` gauges
keep their series identity). No policy can lift slow-worker flows; see
`docs/cos-traffic-shaping.md` for the modeled aggregate-vs-CoV
tradeoff table and #1748 for the work-conserving rebalance track.

The all-class CoS sweep harness captures this estimator as first-class
run evidence. For each class, `fairness-cos-class-sweep.sh` starts a
continuous Prometheus scrape before invoking the multi-sample wrapper
and stops it after the wrapper exits. Raw scrapes are preserved under
`<artifact>/<class>/equal-flow/metrics-raw.prom`; reducer output is
written beside it as `summary.json`, `aggregate.tsv`, and `worker.tsv`.
The reducer reads the multi-sample `summary.json` plus each preserved
`iperf-single.json` and includes only scrapes whose timestamps land
inside the same steady-state window as the fairness verdict
(`start.timestamp.timesecs + WARMUP + EQUAL_FLOW_ESTIMATOR_WINDOW_SECS`
through `start.timestamp.timesecs + duration - FINAL_BURST`). This keeps
suppression-cost estimates aligned with the accepted CoV/Cstruct
samples instead of averaging ramp, cooldown, or post-iperf telemetry.
`WARMUP`, `FINAL_BURST`, and the estimator-window exclusion are
integer-second values to match the `fairness-eval` CLI contract.
Because the equal-flow gauges are themselves rolling 30-second
estimates, the class sweep also skips the first
`EQUAL_FLOW_ESTIMATOR_WINDOW_SECS=30` seconds after warmup by default;
otherwise the first accepted scrapes can still contain pre-steady bytes
inside the gauge's source window.
The sweep also writes `<artifact>/equal-flow-summary.tsv` and appends an
equal-flow section to `summary.md`. Missing or empty scrapes, parse
errors, missing scrape-end markers, non-integer active-worker counts,
missing sample summaries or iperf artifacts, or missing required
aggregate estimator rows for the target `COS_IFINDEX` and class queue
inside the steady-state windows are infrastructure failures and make
the sweep exit `2`; they do not produce a false-green fairness verdict.
- **`xpf_userspace_worker_cos_queue_lease_acquire_v8_calls_total{worker_id=...}`**
  counter: cumulative v8 CoS queue-lease acquire calls made by the
  worker. Use `rate()` over the same scrape window as worker TX
  throughput to test the #1240 hypothesis that some workers request
  queue tokens more frequently.
- **`xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total{worker_id=...}`**
  counter: cumulative bytes granted by those v8 acquire calls. Compare
  per-worker grant rate with per-worker TX byte rate and active-flow
  distribution to separate lease acquisition imbalance from TCP/NIC
  effects.
- **`xpf_userspace_worker_cos_wheel_ticks_advanced_total{worker_id=...}`**
  counter (#1782 Step-1, mechanism (i)): cumulative CoS timer-wheel
  ticks (50 µs each) advanced by `advance_cos_timer_wheel` across the
  worker's bindings. The wheel catches up one tick per loop iteration
  while the lag is within the wheel horizon (65,536 ticks, ~3.28 s);
  since #1782 Step-2 an over-horizon lag with no parked queue is
  snapped in O(slots) instead of replaying `lag / 50 µs` iterations
  inside a single `drain_shaped_tx` call (the confirmed §4(i)
  cold-start mechanism). The counter still records the TRUE lag on the
  snap path. `rate()` is uninteresting at steady state (≈ 20k ticks/s
  per active root); the cold-start signal is a step in the total
  coincident with the first post-idle drain.
- **`xpf_userspace_worker_cos_wheel_ticks_advanced_max{worker_id=...}`**
  gauge (#1782 Step-1, mechanism (i)): largest single-call wheel
  advance ever observed on the worker (monotonic high-water mark,
  never resets). One cold reproduction landing a multi-million-tick
  max pins the O(lag) catch-up conclusively (the Step-1 evidence:
  2,226,212 ticks in one call after ~111 s idle). Since #1782 Step-2 a
  multi-million-tick max no longer implies a multi-million-iteration
  loop — over-horizon advances are snapped in O(slots) while the
  counter keeps reporting the true lag.
- **`xpf_userspace_worker_cos_queue_lease_undergrant_total{worker_id=..., cause=...}`**
  counter (#1782 Step-1, mechanism (ii)): CoS exact-guarantee selector
  visits where, AFTER `maybe_top_up_cos_queue_lease`, the queue's
  tokens still could not cover the head frame
  (`queue.hot.tokens < head_len`, the plan r2-F1 comparison),
  attributed to the `acquire_v8` shortfall cause. Causes:
  `seqlock_give_up`, `cap_zero`, `epoch_rotated`, `share_exhausted`,
  `class_cap`, `outstanding_cap`. A v8-attributed subset of the
  per-queue `drain_park_queue_tokens` counter; under-grants with no v8
  attribution (legacy lease, no lease, fully-granted acquire below the
  head watermark) are deliberately not counted. All six cause series
  emit per worker so first occurrences have a zero baseline.
- **`xpf_userspace_cos_lease_v8_requested_bytes_total{ifindex=..., queue_id=..., worker_id=...}`**
  / **`..._granted_bytes_total`** counters (#1863 Step-0): cumulative
  bytes each worker ASKED of (every `acquire_v8` call with
  `requested > 0`, granted or not) and was GRANTED by a CoS queue's
  shared v8 lease. The pair is the honored-realization-gap attribution
  instrument (docs/pr/1863-realization-gap/plan.md section 5): on
  an undergranting class, a worker with requested >> granted was
  share-bounded while asking (share/demand mismatch), while a worker
  with near-zero requested despite class backlog never sampled its
  share at all (claim-sampling loss). Empty/absent for legacy
  (non-v8) leases. Never reset at lease-epoch rotation — but they ARE
  reset when the lease itself is rebuilt (config commit changing the
  lease identity, HA transitions): the counters live on the lease
  Arc, like every other lease-held counter
  (`equal_flow_cap_hit_events` etc.). Prometheus `rate()`/`increase()`
  handle the reset; raw before/after delta analyses must not span a
  lease rebuild.
- **`xpf_userspace_cos_admission_flow_share_drops_total`** /
  **`..._buffer_drops_total`** / **`..._ecn_marked_total`**
  `{ifindex=..., queue_id=...}` counters (#1863 Step-0): the
  pre-existing per-queue admission-path counters (#710/#718, wire +
  CLI only until now) surfaced to Prometheus so shaped-pipeline drop
  sites are attributable in measurement cells (the #1863 udp3g
  drop-site question).
- **`xpf_userspace_binding_tx_completions_total{binding_slot=..., queue_id=..., worker_id=..., iface=...}`**
  counter: cumulative AF_XDP TX completions reaped by each binding's
  owner worker. Use `rate()` during fairness runs to detect per-RX-queue
  completion-service asymmetry.
- **`xpf_userspace_binding_tx_completion_ring_available{binding_slot=..., queue_id=..., worker_id=..., iface=...}`**
  gauge: last sampled AF_XDP TX completion-ring descriptors available
  before the owner worker drained completions. This is a diagnostic
  status sample, not a scheduler input. The worker resets the local
  sample after publishing; a zero value can mean either no completion
  backlog or no TX work in the last debug window, so disambiguate with
  `rate(xpf_userspace_binding_tx_completions_total[...])`.
- **`xpf_userspace_binding_tx_completion_ring_available_max{binding_slot=..., queue_id=..., worker_id=..., iface=...}`**
  gauge: maximum sampled completion-ring availability in the last
  debug window. Non-zero skew here distinguishes TX completion backlog
  from pure RSS/flow-placement skew. Like the current-value gauge, this
  is reset after each publish and should be interpreted alongside the
  per-binding completion rate.
- **`xpf_userspace_binding_v_min_throttles_total{binding_slot=..., queue_id=..., worker_id=..., iface=...}`**
  counter (#1831, follow-up to #1766): V_min fairness-brake throttle
  decisions on the binding's shared-exact CoS queues — a drain batch
  early-broke because the queue's virtual time ran more than
  LAG_THRESHOLD ahead of the slowest participating peer worker's V_min
  (#917/#943). Non-zero under load confirms the cross-worker brake is
  engaged. The expensive peer-slot V_min scan that backs this brake is
  throttled by a per-queue cadence (`V_MIN_READ_CADENCE = 8`): it runs on
  the first proceeding pop and every 8th pop thereafter. That cadence
  counter (`VMinQueueState::v_min_pop_count`) PERSISTS across the many
  small drain calls a queue takes under low/medium load (#2624); a
  per-call reset would re-arm the full scan on every drain and defeat the
  cadence, raising cross-core coherency traffic without changing the
  throttle decision. The counter advances ONLY over a CONFIRMED pop
  (#2646): the commit is deferred past the gate to after the head item is
  actually removed from its bucket, so a post-gate budget-miss or
  mirror-reserve-miss break (head packet larger than the remaining
  root/secondary budget) breaks WITHOUT advancing the cadence — it no
  longer burns a cadence position while draining zero bytes, which would
  otherwise skip a mandatory/cadence peer snapshot and count a phantom pop
  in exactly the low-budget bursty regime this brake serves. The
  gate-throttle (hard-cap) path is unchanged; only the post-gate pre-pop
  breaks now also skip the advance. UNSHAPED shared-exact queues are
  EXCLUDED from this brake entirely (#2981): `cos_queue_v_min_continue`
  early-returns continue for `transmit_rate_bytes == 0` queues
  ("unshaped/full bucket"), the same disposition as the `!shared_exact()`
  gate. There is no configured rate for an unshaped queue to be fair to,
  so the V_min lag throttle must not apply: were it reached, the
  threshold (`per_worker_rate × 1 ms`, `per_worker_rate == 0`) would
  collapse to the 24 KB floor (~16 MTU, < 2 µs at 100 Gbps) and fire on
  ordinary thread/NIC jitter. This is a DEFENSIVE GUARD — in the current
  build the state is unreachable: a queue is only `shared_exact` when
  `queue_uses_shared_exact_service` admits it, which requires
  `transmit_rate_bytes >= COS_SHARED_EXACT_MIN_RATE_BYTES` (2.5 Gbps),
  and the pre-existing `!shared_exact()` gate already excludes every
  rate-0 queue. The early-return hardens the invariant "unshaped ⇒ not
  V_min-throttled" against any future change that admits a rate-0
  shared-exact queue (mirrors the #917 Codex-Q8 defensive gate); it is
  NOT a fix for an observed runaway throttle. SHAPED queues
  (`transmit_rate_bytes > 0`) are byte-identical — threshold and gating
  decision unchanged.
  #8428 adds two more NOT-APPLICABLE arms to the same brake, and unlike
  the #2981 one these were reachable and fatal. `cos_queue_v_min_continue`
  is gated on `shared_exact()`, and since #1598
  `queue_uses_shared_exact_service` admits on RATE ALONE — a NON-exact
  queue at or above `COS_SHARED_EXACT_MIN_RATE_BYTES` is routed into the
  shared-exact flow-fair drain. But neither of the things the brake reads
  is allocated for such a queue: `promote_cos_queue_flow_fair` builds
  `flow_fair_state` only `if queue.config.exact` (non-exact queues
  promote LAZILY on their second distinct flow), and
  `build_shared_cos_queue_vtime_floors_reusing_existing` skips
  `!queue.exact` DELIBERATELY — its own comment states the divergence:
  "V_min coordination is an exact-only concept ... both gates keep their
  own predicate: shared_exact-routing is broader, V_min-floor is
  exact-only." The brake `.expect()`ed both, so an ordinary
  high-rate uncapped class PANICKED the worker thread — the worker dies,
  its bindings stall, and there is no auto-recovery. Both are now
  `if let` with the same continue-unthrottled disposition as the
  `!shared_exact()` and unshaped arms: a queue with no peer slots has
  nothing to compare against, and one with no virtual time has nothing to
  compare. The fix is deliberately on the CONSUMER side — allocating
  floors for every routed queue would contradict the allocator's stated
  design and, in its words, be "useless work". The containment
  (floor-eligible ⇒ shared_exact-routed, never the reverse) is pinned by
  `a_non_exact_high_rate_queue_gets_no_vtime_floor_8428` so the
  divergence cannot be closed from the producer side unnoticed.
- **`xpf_userspace_binding_v_min_throttle_hard_cap_overrides_total{binding_slot=..., queue_id=..., worker_id=..., iface=...}`**
  counter (#1831): V_MIN_CONSECUTIVE_SKIP_HARD_CAP escape-hatch
  activations — after that many back-to-back throttle decisions the
  drain force-continues and arms suspension (#941 work item D).
  Counted distinctly from (not a subset of) the throttle counter; the
  overrides/throttles ratio is the diagnostic for LAG_THRESHOLD tuned
  too tight. **Rejoin reseed (#4254, R-7):** `queue_vtime` is a
  cumulative served-bytes counter with NO shared epoch, so an absolute
  cross-worker comparison is only meaningful while every participant
  shares a baseline. A worker whose per-interface CoS runtime is rebuilt
  — config commit, XDP rebind, per-binding `reset_binding_cos_runtime` —
  restarts its `FlowFairState` at `queue_vtime = 0`. Left uncorrected,
  its first post-settle publish broadcasts a near-zero vtime; a
  surviving peer terabytes ahead then fails the gate every batch and
  rides the hard-cap → 1000-suspended-drain escape hatch continuously
  (fairness brake effectively OFF, `hard_cap_overrides` the only counter
  climbing). To prevent this, `promote_cos_queue_flow_fair`
  (`cos/admission.rs`) SEEDS a rebuilt shared_exact queue's fresh
  `queue_vtime` to the current cross-worker **peer frontier** — the MAX
  participating peer slot, via
  `SharedCoSQueueVtimeFloor::peer_frontier_vtime`. This is the sole
  reconstruction site for a shared_exact `FlowFairState` (exact queues
  never demote). The MAX (rather than the participating V_min) is the
  do-no-harm seed: a rejoiner placed at the frontier can never become a
  new V_min below an existing peer, so it does not perturb the
  survivors' throttle decisions, yet it still defers to a GENUINE
  laggard (a live peer at a real lower vtime, never reconstructed, hence
  never reseeded — the reseed distinguishes "rejoining at 0" from
  "legitimately behind"). Cold start / full simultaneous reset → no
  participating peer → frontier `None` → seed stays 0 (unchanged). Only
  shared_exact queues carry a `vtime_floor`, so owner-local exact queues
  keep the plain 0 seed.
- **`xpf_userspace_cos_sojourn_windowed_min_ns{ifindex=..., queue_id=...}`**
  gauge (#1829 Phase 1): minimum per-packet queue sojourn over the
  last 1-2 100 ms windows, MAX-merged across workers (worst
  instance). CoDel's standing-queue estimator and the #1829 Phase-2
  gate metric — a value persistently above `codel-target` is
  standing-queue evidence; 0 means no pops in the last ~2 windows.
  Companion gauges `xpf_userspace_cos_sojourn_ewma_ns` and
  `xpf_userspace_cos_sojourn_peak_ns` are supporting context only
  (both biased high by scheduler service gaps). See "Reading the
  sojourn telemetry" in `cos-validation-notes.md`.

Operators tracking this contract in production monitor the gap
`(observed_cov - cstruct)` and the starved-flow counter. A
healthy production system has the gap `≤ 0.05` and the counter
flat.

The RSS-structure gauges above are exported from the production
Prometheus collector. The rolling throughput metrics
(`xpf_fairness_saturated`, `xpf_fairness_observed_cov`, and
`xpf_fairness_starved_flows`) and the #1304 equal-flow estimator are
derived from worker-owned flow-cache byte counters surfaced through the
bounded flow-worker status snapshot. The daemon keeps the 30-second
window in collector state and advances the wall-clock window on every
healthy scrape, even when no flow byte counter moved. Truncated
flow-worker snapshots reset the runtime window and suppress metric
emission rather than reporting a false-healthy queue from stale samples.
Truncated CoS active-flow snapshots suppress only the equal-flow
estimator because the estimator needs both per-worker byte rates and
per-worker active-flow counts. The estimator remains advisory
telemetry. The #1304 shared-v8 equal-flow enforcement mode is opt-in
and intentionally non-work-conserving when configured; its actual
dataplane state is reported by the `xpf_userspace_cos_equal_flow_*`
metrics above.

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
trivially. `fairness-eval` enforces this on the **observed** in-window
1-second bucket count (with a small boundary slack), not on the
self-reported iperf `duration` (hb166 V-7): a truncated JSON that
declares a 120 s run but carries only a handful of intervals is
rejected, and iperf `-O` omitted intervals are filtered out before the
count.

## Regression bounds

For changes that should NOT affect fairness:

- `(observed_cov - cstruct)` regression `≤ 0.02` (2 percentage
  points) vs prior tip on the same fixture.
- Aggregate throughput regression `≤ 5%`.
- Mouse p99 regression `≤ 10%`.
- Starved flow count must not become positive.

For changes that explicitly target fairness improvement:

- The PR body must declare the targeted RSS distribution(s).
- The PR body must say whether the mechanism is intended to stay
  work-conserving or to intentionally slow a shaped CoS queue for
  stricter per-flow equality.
- Work-conserving improvements are measured as **reduction in
  `(observed_cov - cstruct)`**, not as absolute CoV. A change that
  reduces the gap on `{1,3}` distribution from `+0.20` to `+0.05` is a
  clear win; a change that drops absolute CoV from 30% to 25% is
  meaningless if the RSS distribution changed too.
- Non-work-conserving exact-CoS improvements, such as strict
  active-flow-proportional shared-lease budgeting, must report both
  the Cstruct gap and the absolute per-flow spread on the declared
  RSS distribution. These changes are allowed to buy a lower absolute
  CoV by leaving unclaimed worker share idle, but the PR must also
  report aggregate throughput impact.

## Non-goals

xpf does NOT claim, and this contract does NOT require:

- **Global per-5-tuple equality across arbitrary RSS placement.**
  Without hardware steering, cross-worker arbitration, or sender
  ECN backpressure, this is structurally unreachable on AF_XDP
  zero-copy. The structural CoV ceiling `Cstruct` is a hard
  physical limit set by the per-worker scheduler's ability to
  divide its share equally among its flows.
- **Work-conserving equal per-flow throughput within a single
  RSS-skewed deployment** beyond what `Cstruct` permits. The 1+3
  example has a structural minimum CoV of ~58% if every worker is
  allowed to consume its full share. Exact shaped CoS queues may
  deliberately step outside that premise by reserving per-worker
  budget in proportion to active flows and withholding unarmed
  surplus; that is a throughput tradeoff, not a general AF_XDP
  load-balancing guarantee.
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

## CoS oversubscription policy (#1614)

When the sum of an interface unit's configured exact-class
`transmit-rate` exceeds the unit's `shaping-rate`, the dataplane is
in **oversubscription**. The pre-#1614 scheduler is a
**rate-proportional DRR** — every exact class receives roughly
`R_i × shaping_rate / sum(R_j)` bytes/sec under saturation. Math
walk in `docs/pr/1614-multi-rss-cos/plan.md` §3 (committed v5.1)
predicts the observed all-11-class distribution within
quantum-floor noise.

The #1614 v5 scheduler adds an operator-selectable per-interface-
unit policy:

- **`proportional`** (default): current scheduler unchanged
  bit-for-bit. The new allocator code path is never reached when
  this mode is selected AND `priority-low-min-share` is zero
  (see "Bit-for-bit preservation" below).

- **`guarantee-rate <fraction>`** (opt-in): two-phase waterfill
  allocator. Phase 1 honours small-rate exact classes ascending
  by `R_i` up to `fraction × cap`. Phase 2 distributes residual
  proportionally across the queues NOT fully honoured in Phase 1
  (with the partial-honour queue carrying its REMAINING quantum,
  not its full quantum, so total alloc per queue ≤ Q_i).

  **Zero-TX honor refund (hb166 T-2):** the selector debits the
  Phase-1 budget and sets the honored-epoch bit at SELECTION, but the
  service wrapper REFUNDS both (adds the debit back, clears the bit) if
  the selected queue transmits zero bytes — a transient TX failure (TX
  ring full, no free UMEM frame, frame-build Drop) must not burn the
  small class's 200 µs epoch guarantee. The failure is interface-wide
  (all CoS queues share one TX ring / UMEM pool), so a refund + retry
  does not differentially starve other queues; the worker reaps
  completions between drain passes. `phase1_admissions` therefore counts
  only visits that made TX progress; `phase1_selected_no_progress`
  counts the refunded no-progress visits (climbing there with flat
  `phase1_admissions` on a backlogged small class = TX-ring pressure
  eating the guarantee pass). A queue that DID transmit keeps its honor
  consumed — no double-consume, no honor leak. Both counters are
  surfaced (#4262): `show class-of-service interface` renders
  `phase1_no_progress` in the per-queue Waterfill row next to
  `phase1_admit`, and Prometheus exports
  `xpf_userspace_cos_waterfill_phase1_selected_no_progress_total` per
  `{ifindex, queue_id}` (see docs/cos-validation-notes.md).

  **Claim-side work conservation (#1863, Path A-ii):** the per-class
  v8 lease that fuels the selector's token banks publishes a per-epoch
  class budget (`rate × elapsed`) dealt to workers flow-proportionally
  at each 200 µs rotation. Workers claim their share only when the
  drain loop visits their queue, so under heavy competing load a
  worker can miss an epoch entirely; pre-#1863 the missed share
  evaporated at rotation — measured as 21-29% of the class budget for
  honored mid classes under a Phase-2 aggressor (the
  honored-realization gap, docs/research/1863-realization-gap). The
  rotation now banks an epoch's UNCLAIMED class budget into the
  existing bounded lag-carry (`epoch_carry_bytes`, ≤ 8 epochs banked,
  ≤ 7 epochs drawn per rotation, dropped on the ≥256-epoch cold-resume
  path) and the next rotation re-deals it through the same
  flow-proportional share formula. Per-worker isolation is preserved
  (no mid-epoch class-room racing); a fully-claimed epoch banks
  nothing, so the healthy steady state is byte-identical; long-run
  hard caps are unchanged (a banked byte is a published-but-ungranted
  byte — the carry recycles, never mints). Equal-flow
  (`EqualFlowSuppress`) leases are excluded and keep evaporation
  semantics byte-for-byte (suppressed budget must not be re-granted;
  the IdealShare target numerator must not track sampling noise).

Junos configuration:

```
set class-of-service interfaces <iface> unit <u>
  oversubscription-policy guarantee-rate <fraction>     # 0.0..1.0
set class-of-service interfaces <iface> unit <u>
  priority-low-min-share <bps>
```

### Aggregate push ceiling `C_phys` is the per-class denominator (#1578/#1614 §3.A)

Let `C_phys` be the platform's push-direction RX→forward→TX delivery
ceiling — a **hardware** property (CPU, memory bandwidth, PCIe, worker
count), NOT a CoS scheduler limit. On the standard `loss:` reference
cluster (6 mlx5 VF RX queues → 6 workers) `C_phys ≈ 22-24 G`, measured
consistently across 3-large (22.6 G), 6-large (21.6 G), full-11
(24.96 G) push and the 22.72 G reverse sanity (#1578, #1614 §2). It is
**not** a universal product constant; a different platform (different
core count, NIC, or PCIe layout) has a different `C_phys`.

The denominator every *backlogged* class divides is `C_phys`, NOT the
sum of configured `transmit-rate`. On the `cos-iperf-config.set`
fixture the configured exact-shape sum is **109 G — roughly 4.5×
`C_phys`** — so strict-exact is not simultaneously deliverable. The A4
commit warning (#1618) fires on exactly this `sum_exact > shaping_rate`
condition. `park_root = 0` everywhere in the #1614 capture, so the 25 G
root token bucket never throttles — the limiter is upstream of the root
token gate, in the forwarding/TX path.

When N classes are simultaneously backlogged, `C_phys` divides among
them, so per-class %-of-shape **drops as N rises**. Measured
competitor-count sweep (#1614 §2.4): 3g reaches 94% solo, 69% with one
competitor, 54% with four — the deficit is set by HOW MANY classes are
backlogged, not by 3g's owner worker. 18g pushed 14.25 G from a single
owner worker (`park_root=0`), so the ceiling is an aggregate property,
not a per-worker funnel. Under full-11 simul the small classes
therefore land far below their solo rates (#1614 §2.1: 100m=86%,
1g=63%, 3g=43%, 6g=41%) — this is ceiling-division physics, not a
scheduler defect.

**Reading divided-ceiling as starvation is a misread.** A guaranteed
class `i` (guarantee `G_i = R_i × guarantee-rate fraction`) is
**starved** iff ALL THREE hold:

1. `actual_i < G_i` — the guarantee is unmet; AND
2. `Σ actual_j > 0` over the *unguaranteed* classes — they ARE getting
   bandwidth while `i` is short; AND
3. `Σ G_k < C_phys` over the *guaranteed* classes — the guaranteed
   demand fits under the ceiling, so there is recoverable headroom.

If `Σ G_k ≥ C_phys`, or all unguaranteed classes sit at 0 G while
`C_phys` is saturated, the shortfall is divided-ceiling physics, NOT
scheduler starvation. `C_phys` is not directly emitted at smoke time,
but condition 3 is conservatively checkable as `Σ G_k < total_recv`
(the achieved aggregate is a lower bound on `C_phys` under saturation).
The #1614 §3.B 3g/6g case satisfies all three (small4+24g: `Σ G_k`
fits under the 18.2 G achieved, 24g getting 12.6 G, 3g/6g at 54/51%) —
that is the genuine defect SIGNAL, tracked separately in **#1692**
(instrument-first; mechanism unresolved, no fix chosen here).

### Acceptance gates under guarantee-rate mode

**Per-flow fairness gate (the only one):** the structural #1217
contract above, `observed_CoV ≤ Cstruct + 0.05`. The flat per-flow-CoV
gate the original #1614 issue body proposed (body acceptance-line
"Per-flow CoV ≤ 5% under simultaneous load") is **DROPPED**: per
#1220/#1244 the per-flow CoV within a class is structural — at the
multinomial(12,6) RSS floor `Cstruct ≈ 53%` — so a scheduler change
that does not move per-flow placement cannot lower it, and a flat
5/10% bar is structurally unreachable. (The #1614 body already cites
#1217 elsewhere; this rescope resolves that internal inconsistency.)

**Per-class %-of-shape gates are bounded by `C_phys`** (see "Aggregate
push ceiling" above): no simul-load gate may assert per-class numbers
whose sum exceeds `C_phys`. The ≥95% small-class absolute guarantee
(gate 1 below) is achievable **SOLO or with few competitors only** —
under full-11 simul the `C_phys` division puts even 1g at 63%, so that
guarantee is asserted by the SOLO harness `cos-gate1-small-four-alone.sh`
(#1630), NOT the full-11 `cos-simul-load-smoke.sh`. The full-11 simul
harness instead asserts a **divided-ceiling regression floor** (gate 1
below) that catches a collapse, not the unmet guarantee.

guarantee-rate runs assert:

1. **Small-class absolute guarantee — SOLO / few-competitor only**
   (classes whose cumulative `R_i` fits under the shaping ceiling):
   each class hits ≥ 95% of its configured rate. This is verified by
   `cos-gate1-small-four-alone.sh` (#1630, SOLO one class at a time or
   the small-four-alone run), where 100m/1g reach 95.0/95.3%. Under
   **full-11 simul** the `C_phys` division makes ≥95% unreachable for
   every class (100m=86%, 1g=63%, 3g=43%, 6g=41%; #1614 §2.1), so the
   full-11 `cos-simul-load-smoke.sh` gate 1 is a **divided-ceiling
   regression floor** instead: each of 100m/1g/3g/6g must stay above a
   relaxed per-class floor calibrated below its measured simul value
   (100m ≥ 60%, 1g ≥ 40%, 3g ≥ 25%, 6g ≥ 25% of shape) so a collapse
   (e.g. starve-to-zero) trips while normal ceiling-division does not.
   The ≥95% guarantee for 3g/6g under multi-class contention is a
   CONFIRMED-but-mechanism-UNRESOLVED defect tracked in **#1692**; it
   is not asserted here until that issue resolves.
2. **Priority-low minimum share**: **DEFERRED / NOT IMPLEMENTED.**
   The intended gate — when configured, the priority-low queue
   receives ≥ 95% of its configured `priority-low-min-share` — is
   NOT satisfied by any engine path. `priority-low-min-share`
   (#1614 A2) is wire-surface only: it is typed, validated at
   commit, and stored, but no scheduler code consults it (the
   `cap_eff` per-pass reservation that would enforce it does not
   exist; see `afxdp/types/cos.rs` "Currently UNUSED" and the note
   in `afxdp/cos/queue_service/mod.rs`). A commit warning surfaces
   the inertness. Enforcement is deferred research (#4220); until it
   ships this gate must not be asserted.
3. **Retransmit floor**: per class ≤ 100 retransmits per 30 s
   under all-class simul load (gate 3 of plan.md §7). Achieved by
   the A3 CoDel-style sojourn-time AQM (default disabled; opt-in
   via `set class-of-service schedulers <name> codel-target <ms>`).
4. **Proportional regression preserved**: a config without the
   new `oversubscription-policy` keys produces the same per-class
   distribution as master HEAD on the `cos-iperf-config.set`
   fixture (within ±5% per-class token-bucket noise).

### Small-class per-class rate-metering floor (#1630 cause-1)

Even SOLO (one class, one port, zero competition) the lowest-rate exact
classes could not reach their configured shape — a per-class floor in the
v8 epoch rate-meter, independent of cross-class competition. A SOLO A/B
isolated TWO distinct root causes:

- **cause-1** (fixed here): the rotation rate-meter clamp + sub-frame
  selector discard, which pinned 100m at ~81 % and 1g at ~84 % of shape;
- **cause-2** (a transport-physics floor, NOT a scheduler defect, see
  below): a `K`-independent mid-rate residual on 3g/6g.

Cause-1 has two composing parts:

- **Bounded rotation credit carry** (`rotate_epoch_v8`). The epoch
  rotation is purely lazy — a low-rate class is only rotated when the
  scheduler next visits its queue, so the gap (`lag`) between two
  rotations of the same queue routinely exceeds one epoch. The previous
  clamp computed `elapsed = min(lag, EPOCH)` and reset
  `epoch_start := now`, permanently discarding `rate × (lag − EPOCH)` of
  grant. The replacement bounds `elapsed` by `K × EPOCH`
  (`MAX_ROTATION_LAG_EPOCHS = 8`) to recover the lagged credit, banks any
  residual beyond `K` into a clamped per-class carry deficit drained on
  the next visit, and COLD-RESUMES to a single epoch (dropping carry) for
  any lag beyond `STALL_THRESHOLD_EPOCHS = 256` so a stalled or
  HA-failed-back worker (reused lease, stale `epoch_start`) cannot emit a
  multi-epoch burst. The per-rotation grant is hard-bounded by
  `(K + (K−1)) × rate × EPOCH`, preserving the burst bound (Gate 4) the
  old clamp protected.
- **Per-visit frame-count cap + N-frame token bank** (P2 + P1). The
  guarantee selectors clamped each visit's send budget to the rate-scaled
  quantum (`rate × 200 µs`), below two MTUs for a low-rate class, so the
  drain sent one frame and discarded the sub-frame remainder every visit.
  The send budget is now `cos_guarantee_visit_cap_bytes`
  (`TX_BATCH_SIZE × frame`) while the Phase-1 budget gate keeps the
  rate-scaled quantum (`phase1_cost`) so small-first ordering is
  preserved; the exact-queue token bucket banks an N-frame burst
  (`COS_EXACT_QUEUE_LEASE_BANK_BYTES`, N = 8) with the outstanding-credit
  cap raised in lock-step. The long-run rate is still metered by the v8
  per-epoch grant and the actual-byte debit, so the hard-cap holds.

Measured effect of cause-1 (loss userspace cluster, reth0.80,
`guarantee-rate 0.7`, 12 streams, push, v4, SOLO one class at a time):

| Class | master baseline | cause-1 (this fix) SOLO |
|-------|----------------:|------------------------:|
| 100m  | ~81 %           | **95.0 %** |
| 1g    | ~84 %           | **95.3 %** |

The scoped acceptance gate is 100m and 1g each ≥ 95 % of shape **SOLO**
(`cos-gate1-small-four-alone.sh` run one class at a time, or the per-port
SOLO loop). The four-classes-in-parallel variant of that harness and the
IPv6 path land 1-3 pp lower (parallel cross-class contention + the v6
per-packet header overhead push the small classes onto the cause-2
physics floor below); those are reported for the record, not as the
pass/fail bar.

### Mid-rate transport-physics floor (#1630 cause-2 — documented, not fixed)

The mid-rate exact classes (3g/6g) carry a `K`-independent ~6 % shape
residual that **no scheduler change recovers** — it is single-TCP-flow-
bundle, ACK-clocked bursty delivery that cannot keep one worker's
per-CPU AF_XDP token bucket continuously full (measured queue park
19-117K/s, root never throttling, `parkR = 0`). The decisive
discriminator (cause-2 §5 measurement on #1630): drain-sent / shape is
WORST at `-P1` (single worker, whole-class cap ≈ 0.878) and RECOVERS with
parallelism (`-P4` ≈ 0.918, `-P12` ≈ 0.949). A cross-worker fair-share
bug would WORSEN with more workers; this IMPROVES — so it is transport
physics, not a fairness defect. At high parallelism (`-P12`) the mid-rate
classes reach ~93-95 % of shape; at low parallelism they sit lower,
bounded by the token-bucket fill rate a bursty single flow can sustain.
This floor is therefore a documented characteristic of the per-CPU
AF_XDP + token-bucket transport, NOT a `guarantee-rate` Gate failure, and
is intentionally not a pass/fail bar.

#### Candidate recoverable mechanism: v8 epoch-ledger double-charge (#4246, T-1)

The "transport physics" attribution above is a *default* explanation, not
a proof. #4246 (fable-review-166 finding T-1) identified and fixed a v8
shared-CoS-lease accounting bug that reproduces cause-2's exact
parallelism fingerprint and is therefore a **plausible, falsifiable
alternative** to (or co-factor of) the transport-physics floor.

- **The bug.** `acquire_v8_with_cause` charges every grant to THREE
  ledgers — the per-epoch class ledger `packed_granted` (the word the
  ClassCap gate reads), the legacy `outstanding` credit, and the
  per-worker `worker_grants[worker_id]`. The give-back `release_unused`
  only freed the legacy `outstanding` word; it never decremented
  `packed_granted` or `worker_grants`. Rotation banks only `cap -
  granted`, so released-but-not-recredited bytes stayed charged for the
  rest of the epoch. A mid-rate exact class oscillating empty↔backlogged
  at epoch timescale hit ClassCap early and parked until the next
  rotation (~94% service).
- **Why it matches the cause-2 fingerprint.** T-1 is NOT a cross-worker
  fair-share bug (those worsen with more workers). It is a *per-queue*
  epoch-ledger double-charge whose FREQUENCY is driven by the
  empty↔backlogged transition rate. At `-P1` a bursty single flow empties
  the queue often → many releases → more double-charging → worse. At
  `-P12` the queue stays backlogged → fewer empties → less double-charging
  → better. So the discriminator the doc used to rule out a fairness
  defect ("improves with parallelism ⇒ transport physics") does NOT rule
  out T-1.
- **The fix.** `SharedCoSQueueLease::release_unused_v8(worker_id, bytes)`
  (`types/shared_cos_lease/lease.rs`) mirrors the acquire path's
  `tag_checked_rollback` CAS discipline: claim the credit from the
  worker's current-epoch grant slot (tag-checked, capped at what the slot
  holds so a cross-epoch release safely no-ops), then decrement
  `packed_granted` by the same claimed amount. Both v8 queue-lease
  give-back sites (`tx_completion.rs` on queue-empty, `token_bucket.rs` on
  teardown) route through it. Folds R-5(a): the same `tx_completion.rs`
  site used to destroy a no-lease exact queue's banked burst by
  `mem::take`-ing `hot.tokens` unconditionally; the take is now gated on
  lease presence.
- **Falsification test.** `release_unused_v8` accumulates a diagnostic
  `release_recredited_bytes` counter (per-lease, `v8_release_recredited_bytes()`).
  Sum give-back bytes against the per-class undershoot on a mid-rate
  on/off iperf pattern: if re-credited bytes correlate with the
  undershoot, cause-2 is (at least partly) this ledger bug. If the ~6%
  residual persists on the loss userspace cluster after this fix with no
  correlation, cause-2 is confirmed transport physics. **The accounting
  fix is correct on its own merits regardless of the cause-2 outcome** —
  it eliminates a genuine over-charge that parked mid-rate classes early.
  Needs a cluster CoS mid-rate multi-class smoke to measure the recovery.

#### Fairness-accounting lifecycle fixes (hb166 R-1/R-3/R-4)

Three further fable-review-166 findings are state-lifecycle defects in
already-shipped fairness mechanisms — invisible to steady-state iperf
smoke, real under flow churn / low-rate classes / weak-memory CPUs. All
three are pure accounting corrections (no policy change). R-1 and R-4
carry RED-on-revert unit tests (the fix reverted, the named assertion
fails). R-3 is a memory-ordering fix whose failure is only observable on
a weakly-ordered CPU (ARM/POWER) or under a loom model — it is NOT
reproducible on the x86-TSO CI/deploy host — so it carries a structural
ordering guard that asserts a cross-field snapshot invariant a torn read
would break, not a RED-on-revert test.

- **R-1 — recycled MQFQ bucket inherits a dead flow's rate (#4259).** The
  cap-aware per-flow selector (`cos_queue_min_finish_bucket`,
  `queue_ops/mod.rs`) defers any bucket whose per-bucket observed-rate
  EWMA (`account_flow_bucket_tx`, `cos/fairness.rs`) exceeds the fair-
  share target. That EWMA decays only on TX commits (which need service)
  and its skip-ramp re-arms only at 0, but the bucket-idle reset in
  `account_cos_queue_flow_dequeue` (`queue_ops/accounting.rs`) cleared
  only the head/tail finish tags — the observed rate survived flow death.
  A newcomer hashing into a recycled bucket was throttled with the
  departed elephant's rate (the mechanism built to protect cool flows
  throttling the coolest). Fix: on the bucket nonzero→0 transition (the
  bucket-identity boundary) also zero `flow_bucket_observed_bps` /
  `flow_bucket_last_tx_ns` / `flow_bucket_pending_bytes`, mirroring the
  existing finish-tag reset (a drain to 0 is treated as idle/recycled).
  The monotonic lifetime counter `flow_bucket_tx_bytes` is preserved. The
  positive action of the cap-aware selector (defer-at-finite-target) was
  previously untested and is now pinned.

- **R-3 — v8 epoch seqlock writer missing the Release fence (#4260).**
  `maybe_rotate_epoch_v8` claims the rotation with an AcqRel EVEN→ODD CAS,
  writes the payload with Relaxed stores, and publishes with the final
  Release ODD→EVEN store (the #1643 reader-fence's partner). The AcqRel
  claim's Release half orders only writes *before* the CAS; no reader
  synchronizes-with it by reading the ODD value. So on a weakly-ordered
  CPU a payload store could become visible before the ODD claim, and a
  reader could read seq=EVEN(old) / new payload / seq=EVEN(old) and accept
  a cross-epoch mix (the #1619 tearing class, of which #1643 fixed only
  the reader half). Fix: `fence(Ordering::Release)` immediately after the
  successful claim CAS (Boehm's seqlock recipe) — one fence per rotation
  (~200 µs). Latent on the x86-TSO deploy targets; a real hazard on
  ARM/POWER. The crate has no loom dependency, so the guard is a
  contention test asserting the cross-field `grace == tag*EPOCH + EPOCH/2`
  invariant a torn snapshot would break.

- **R-4 — token-bucket refill drops fractional dust (#4261).**
  `refill_cos_tokens` (`cos/token_bucket.rs`) floored the byte grant
  (`added = elapsed×rate / 1e9`) but advanced `last_refill_ns` fully to
  `now_ns`, discarding `< 1` byte of accrued credit every refill. At
  64 kbps on the ~200 µs drain cadence that is 1.6→1 B/interval — a 37.5%
  shortfall a kbps voice/control class never recovers (~2% at 1 Mbps,
  negligible ≥100 Mbps). Same failure shape as #1630 cause-1, one decade
  lower — the ns-integer-division dust layer under the epoch/visit-cap
  layer #1630 fixed. Fix: carry the fractional remainder in the timestamp
  — rewind `last_refill_ns` by the time-equivalent of the ungranted
  fraction (`remainder / rate`) instead of advancing to `now_ns`, so
  cumulative granted == `floor(total_elapsed × rate / 1e9)`. No new field
  or signature change; the remainder lives in the timestamp, mirroring the
  #1630 byte-carry precedent one decade up.

All three need a cluster CoS smoke (a fairness-mechanism change): the
per-class SOLO/simul-load harness for R-1/R-4, and — because R-3 cannot
be reproduced on x86-TSO — a functional CoS smoke to confirm the added
writer fence is behavior-neutral on the deploy targets.

#### TX-path MEDIUM cluster fixes (hb166 T-6, #4267)

The fable-review-166 T-6 grouped TX-path cluster enumerated 13 CoS
correctness/robustness sub-items (a–m). #4245 classified them 7 READY /
6 DEFER; #4267 drives the six that are cleanly bounded at current master
(after R-7/#4255, T-1/#4253, T-2+T-5/#4258, R-1/R-3/R-4/#4264 merged).
Each carries a RED-on-revert unit test.

- **T-6(a) — V_min suspended-batch telemetry + decaying re-arm.** The
  V_min hard-cap arms `V_MIN_SUSPENSION_BATCHES` (1000) suspended drains
  (`queue_ops/v_min.rs`), but `cos_queue_v_min_consume_suspension` counted
  none of them — only the activation (`v_min_hard_cap_overrides`) — so
  telemetry read "brake idle" while it was actually suppressed ~99% of the
  time under persistent skew. Fix: a `v_min_suspended_batches` counter
  (full scratch→atomic→snapshot→wire plumbing, mirrors `v_min_throttles`,
  Go `VMinSuspendedBatches`) plus a decaying re-arm — each consecutive
  hard-cap (no intervening passing V_min check) halves the suspension
  window toward `V_MIN_SUSPENSION_MIN_BATCHES` (64), and a clean check
  restores the full window — so a persistently-skewed queue re-engages the
  brake progressively sooner. R-7/#4255 fixed the *root cause* of the trap
  (rejoiner reseed); this is the telemetry + re-arm half of the same pair.

- **T-6(b) — work-conserving exact-demand surplus reservation.** The
  best-effort surplus reservation counted an exact guarantee class as full
  demand (reserving its whole rate from the BE residual) merely for being
  non-empty (`root_exact_demand_queue_mask`, `queue_service/mod.rs`;
  `exact_backlog_queue_mask`, `tx_completion.rs`) — even when the class was
  v8-starved / token-parked and shipping zero bytes, starving BE while the
  link idled. Fix: a shared `cos_exact_queue_serviceable` predicate
  (`queue_ops/mod.rs`) — runnable ∧ non-empty ∧ root/queue tokens cover the
  head — gates BOTH the local demand mask AND the published peer-demand
  mask, aligning them with the serviceability signal
  `serviceable_exact_backlog_bytes` already publishes. A non-serviceable
  class now releases its residual to best-effort. This touches the
  #1368/#1371 BE-vs-exact contention contract — **needs a cluster CoS smoke
  before merge** (confirm BE reclaims idle bandwidth without under-serving
  a briefly-parked exact class). The "budget-0 queues never park / no wake
  source" half of (b) is a separate wake-source design and stays deferred.
  **#9365:** both demand masks were `u64`s keyed by the index into ALL of the
  interface's queues, so a serviceable queue at index >= 64 saturated the
  mask and consumers counted every exact queue at index >= 64 whenever the
  mask was non-zero — idle exact classes kept their rate reserved and a pure
  best-effort class (surplus is its only service path) lost all service. The
  two per-file copies are now one producer/consumer pair
  (`serviceable_exact_demand_mask` / `exact_demand_rate_bytes_for_mask`,
  `cos/exact_demand.rs`) over `ExactDemandQueueMask`
  (`types/shared_cos_lease/backlog.rs`), one bit per u8 queue id, so every
  committed interface is tracked exactly; the published peer slot carries all
  four words.

- **T-6(e) — V_min publish on the CoSBatch settle path.** The CoSBatch
  submit path (`submit_local`/`submit_prepared`) was the 5th of 5 V_min
  settle boundaries but never called `publish_committed_queue_vtime`; the
  four direct-service sites in `service.rs` do. Surplus-phase shared_exact
  service advanced `queue_vtime` during batch build but never broadcast it,
  so peers read a stale-low V_min slot and self-throttled exactly when
  surplus works hardest. Fix: add the post-settle publish (no-op for
  non-flow-fair / non-shared queues).

- **T-6(g) — admission drops stop double-reporting as tx_errors + stop
  allocating.** A designed CoS admission drop (`flow_share`/`buffer`
  exceeded, `tx/cos_classify.rs`) — already counted in the dedicated
  `admission_flow_share_drops`/`admission_buffer_drops` counters — ALSO
  bumped the aggregate `tx_errors` (an operator reads a saturated shaper as
  a fault) and allocated a per-drop `set_error(format!())` String, ~1M
  allocs/sec under a shaping-drop storm (a hot-path-allocation-rule
  violation). Fix: drop both; keep the non-allocating `dbg_cos_queue_overflow`
  disambiguation counter. The per-drop `format!` in the `bound_pending_tx_*`
  overflow loops (`tx/drain/mod.rs`) is removed for the same reason.

- **T-6(d) — transmit_batch Drop-unwind order.** The oversized-frame
  error unwind in `transmit_batch` (`tx/transmit/mod.rs`) drained the
  staged prefix forward and `push_front`-ed each item, REVERSING same-flow
  (in-order TCP) segments back onto `pending`. Fix: `.drain(..).rev()`
  (the idiom already used in `tcp_segmentation.rs`).

- **T-6(m) — BA classification for fragments / flowless packets.**
  `resolve_cos_tx_selection` / `resolve_cached_cos_tx_selection` returned
  the default queue whenever `flow_key == None` (fragments, flowless),
  bypassing DSCP / 802.1p behavior-aggregate classification despite the
  DSCP being present — so EF fragments straddled queues. BA classification
  is 5-tuple-independent; the fix runs the DSCP→802.1p→default lookup from
  `meta` in both None branches.

- **T-6(f) — submit_local sidecar desync on a mid-batch mirror drop
  (#5157).** `submit_local` (`queue_service/submit_local.rs`) builds its
  per-item `(bucket, bytes)` / `enqueue_ns` sidecars in ORIGINAL input
  order, then charged `sidecar[..packets]` — a PREFIX — after
  `transmit_batch` returned only a committed *count*. But `transmit_batch`
  (`tx/transmit/mod.rs`) drops a `mirror_clone` request mid-batch via
  `continue` when `free_tx_frames.len() <= MIRROR_TX_FRAME_RESERVE` — a
  NON-prefix / interior removal — so after a front/interior mirror drop
  the committed set is no longer a prefix of the sidecar: entry K stopped
  matching the K-th shipped packet. The dropped mirror's bucket was
  charged bytes it never sent, and the shifted real packet's bucket was
  missed, corrupting the per-bucket `flow_bucket_tx_bytes` / observed-rate
  EWMA (R-1's mechanism) and the sojourn EWMA of the wrong flow. Fix:
  `transmit_batch` now reports the ORIGINAL-input positions it actually
  committed in a per-binding scratch buffer
  (`scratch.scratch_committed_orig_idx`, filled in the settle loop from a
  stage→original index map), and `submit_local` accounts both sidecars by
  those identities instead of a prefix — set-sum, order-independent. The
  mirror-reserve back-pressure itself is unchanged (still drop when free
  frames `<=` reserve); only the ACCOUNTING attribution is corrected.
  RED-on-revert unit test
  `mirror_interior_drop_preserves_sidecar_attribution_5157`.

**Deferred T-6 sub-items (recorded in #4267):** (k) coordinator-side
scrub on binding unregister — overlaps R-7's reseed + the existing
worker-side `vacate_all_shared_exact_slots_for_binding`; a safe scrub that
distinguishes membership-change from legit Arc-reuse (without clobbering
the deliberate additive `rehydrate_worker_active_count` or scrubbing live
vtime slots) needs its own analysis + failover smoke. (c) ECN aggregate
arm, (h) inbox-overflow fallbacks, (i) `max_total_leased` bank floor, (j)
equal-flow divisor, (l) truncating-zip / FIFO-settle sojourn — each needs
its own design decision or repro. ((f) sidecar desync is FIXED above,
#5157.)

### Non-exact guaranteed classes are metered class-wide (#4265, R-2)

A **non-exact** guaranteed class whose transmit-rate trips
`COS_SHARED_EXACT_MIN_RATE_BYTES` (2.5 Gbps) runs the sharded
`shared_exact` execution policy — it drains locally on EVERY worker
rather than being funnelled to one owner (#1598 admitted non-exact
high-rate queues to sharded service to lift the single-worker AF_XDP
UMEM ceiling). But its GUARANTEE-phase service goes through
`select_nonexact_cos_guarantee_batch` (not the exact waterfill), which
until #4265 refilled a **private per-worker** token bucket at the FULL
configured rate. With N workers each independently refilling at the full
rate, the class was admitted at up to **N × its configured guaranteed
rate** at guarantee priority — e.g. a 1g non-exact guarantee could take
~6 Gb/s on the 6-worker loss cluster. The excess bypassed both the
surplus-phase DWRR and the `SharedCoSExactBacklog` residual bound (the
whole cross-worker constraint machinery constrains only the surplus
leg). Same CLASS of over-admission as the closed #4002 / #2955 (split
per-worker state), different still-open site.

- **The mechanism.** `worker/cos/mod.rs` attached a `shared_queue_lease`
  to the queue fast-path only when `queue.exact`; the coordinator
  (`build_shared_cos_queue_leases_reusing_existing`) only ever built a
  `SharedCoSQueueLease` for exact queues. So the class-wide metered
  refill path in `maybe_top_up_cos_queue_lease` was unreachable for
  non-exact queues, and the selector fell to the unmetered per-worker
  `refill_cos_tokens`.
- **The fix.** The coordinator now builds a **shared LEGACY lease**
  (`SharedCoSQueueLease::new` — v8=None, a greedy-aggregate shared token
  bucket all workers draw from) for non-exact guaranteed queues whose
  rate qualifies for sharded service, keyed and Arc-reuse-disciplined the
  same way as the exact v8 leases (a worker join/leave changes
  `active_shards` and rebuilds the lease via `matches_config`). The
  worker attaches it unconditionally; `select_nonexact_cos_guarantee_batch`
  refills through `maybe_top_up_cos_queue_lease` (its pre-existing but
  previously-unreachable non-exact-with-lease branch); the guarantee-phase
  send debits the lease via `maybe_consume_exact_queue_lease` (no longer
  gated on `exact`); and the queue-empty give-back returns unspent credit
  through `release_unused_v8`, which reduces to the legacy `release_unused`
  for a v8=None lease. Aggregate guarantee admission is therefore metered
  to the configured rate while staying work-conserving — a single busy
  worker can drain the whole shared pool when its peers are idle
  (rate-division would instead cap that worker at rate/N; the shared lease
  avoids that starvation/waste tradeoff). Because the legacy lease has no
  v8 epoch ledger, it is not subject to the #4246 T-1 / R-5(a) hole.
- **Single-owner queues are unchanged.** A non-exact queue below the
  sharded-service rate threshold stays single-owner (one worker services
  it; no over-admission) and gets no lease; the selector still refills its
  private bucket exactly as before.
- **Test.** `nonexact_guarantee_shared_lease_bounds_aggregate_admission_across_workers`
  (queue_service tests) drives N=6 worker replicas sharing one lease over
  a 20 ms window and asserts the summed admission stays near the
  configured rate (RED — ~N× — on revert to the per-worker refill);
  `nonexact_guarantee_refill_is_gated_by_shared_lease_pool` pins that an
  empty shared pool starves the selector rather than leaking a private
  full-rate refill. Needs a cluster CoS smoke with a non-exact guaranteed
  class on a shared multi-worker egress to confirm the aggregate cap on
  real traffic (the standard fixtures use exact classes, so this does not
  fire on the canonical smoke matrix).

### Simul-load harness

`test/incus/cos-simul-load-smoke.sh [push|reverse]` runs all 11
canonical classes in parallel for 30 s and reduces a verdict.json
with per-class achievement, CoV, retransmits, and gate booleans.
This is now part of the canonical smoke matrix for any PR that
touches CoS scheduling.

**CoV column semantics (#4239 V-10):** the printed `wrCoV%` column is a
**whole-run population CoV** computed by `test/incus/fairness_cov.py`,
the single Python mirror of the Rust fairness SSOT
(`userspace-dp/src/fairness.rs::compute_observed_cov`). It uses the
population estimator (denominator N, not the sample N-1 that
`statistics.stdev` returns) and counts starved (0 bps) flows rather than
filtering them, so a fully starved class raises CoV instead of printing
`0.0` (the "perfectly fair" value). It is labelled *whole-run* because it
covers the entire run including warmup, whereas `fairness.rs` reduces the
steady-state window — the estimator FORM matches; the window does not.
The CoV column is decorative context, not a gate (per the #1614
re-scope). `test/incus/fairness_cov_test.py` pins `population_cov` to the
exact values asserted by the `fairness.rs` unit tests.

**Exit-code contract (#4239/#4240):** the reducer propagates the gate
verdict as the process exit status — the script exits **0 only when
every gate passes**, and **nonzero on any gate failure** (a starved
class, a missing/errored generator, or a nonzero iperf3 rc). Both
`cos-simul-load-smoke.sh` and the SOLO `cos-gate1-small-four-alone.sh`
follow this contract, so `&&`-chained or CI invocation fails loudly
instead of passing on a printed `FAIL`. The generators no longer swallow
failures with `|| true`: each writes a per-port `.rc` sidecar, and
`gate_0` fails on a nonzero (or missing) rc **or** on a rc==0 run that
emitted an unparseable, `{"error": ...}`, or truncated JSON payload —
even for a class no throughput floor reads.

### Bit-for-bit preservation of proportional mode

When `oversubscription-policy` is unset (or set to `proportional`)
AND `priority-low-min-share` is zero, the v5 selector hits an
explicit early-return that routes to the legacy
`select_exact_cos_guarantee_queue_with_lease_telemetry`
unchanged. No round-robin cursor change, no quantum scaling, no
new arithmetic. Existing deployments see no behaviour change.

The Phase 0 sanity check that #1614 v5 was built upon ran on
2026-05-27 against the loss userspace cluster: simul-load reverse
direction (all 11 classes parallel) reached 22.72 G aggregate
with generator CPU 20-58% idle, confirming the firewall (not the
generator) is the bottleneck the work targets. This 22.72 G reverse
number is the reverse-direction counterpart of the push-direction
`C_phys` ≈ 22-24 G documented in "Aggregate push ceiling `C_phys` is
the per-class denominator" above — both directions hit the same
hardware delivery ceiling on this cluster, NOT a CoS scheduler limit.

## What the mouse-latency gate can and cannot render a verdict on (#8277)

The mouse-latency gate measures a small-flow tail under elephant load. Its
§4.2 validity rules decide which reps reach the verdict, and one of them
determines which PHENOMENA the gate is capable of failing on at all. Stated
here because "the instrument cannot see this shape" is not visible from a run's
output — a cell that cannot fail looks exactly like a cell that passed.

| tail shape | before #8277 | now |
|---|---|---|
| **uniform slowdown** — every coroutine slows together | FAIL, correctly. The median moves with the min, so `min/median` stays near 1 and the rule does not fire | unchanged |
| **concentrated tail** — a minority of flows starved, the rest healthy | **could not FAIL.** The starved flows complete far fewer transactions, `min < 0.5 * median` fires, and enough such reps leave the cell at `INSUFFICIENT-DATA` | FAIL, when the starvation is attributable to the echo path |
| **client-side artifact** — a coroutine starved by the probe's own event loop or local socket backpressure | invalidated, correctly — this is what the rule was written for | unchanged; still invalidated |

### How the two are told apart

The degenerate-coroutine rule is a **fairness** predicate. It was applied as a
**validity** predicate, and a gate that exists to detect a tail cannot treat
"the tail is concentrated" as a reason to discard the evidence. But deleting
the rule would re-admit the client-side artifact it was written for, so the
distinction is made from data the probe already records rather than by removing
the check.

For each starved coroutine, `attribute_starvation`
(`test/incus/mouse_latency_probe.py`) compares the three per-coroutine phase
maxima the run already emits — `max_read_us`, `max_sleep_overshoot_us`,
`max_drain_us` — and takes the largest:

- `read_us` dominant → the time went to the **echo path**. That is the thing
  being measured, so the rep is a RESULT and is admitted.
- `sleep_overshoot_us` (timer wake delay in the probe's own event loop) or
  `drain_us` (local socket backpressure) dominant → **client-side**. The rep is
  measuring the probe, and stays invalid.

The comparison is threshold-free deliberately. An arbitrary cutoff is what put
this rule in the position of invalidating its own phenomenon, and the observed
separation is not marginal: #8277's recorded run had `read_us` p99.9 of
740–1349 ms against `sleep_overshoot_us` of 3.1–3.6 ms and `drain_us` of
53–69 µs.

**A rep is admitted only when EVERY starved coroutine is attributable to the
echo path.** One client-side or unattributable coroutine invalidates the rep.
That is the conservative direction, and it keeps the original rule's full power
over the artifact it was written for. A coroutine that completed nothing
records no phase maxima and is therefore unattributable, not admitted.

Whichever way it goes, the rep records a `validity.starvation` block naming the
starved coroutines and their attribution — so a rep admitted *despite*
starvation is distinguishable in `probe.json` from one that never starved.

### What this does not fix

- **Attribution of the verdict itself.** #8259 was the separate defect that
  mice and elephants terminate on the same host, so a loaded/idle ratio could
  not separate firewall queueing from target-host service. Loosening this rule
  lets a concentrated tail produce a FAIL; #8259 is what makes that FAIL mean
  something, and neither subsumes the other. **The second target is now
  provisioned** (`test/incus/mouse-target-setup.sh`, `MOUSE_TARGET_V4`), so
  both halves are in place and the fixture can produce an attributable verdict
  for the first time — which is the run #1359 item 3 has been waiting on.
- **The `error_rate >= 0.01` rule**, which #8277 notes is the same shape: a
  connection error rate that rises *because* flows are being starved is a
  result, not a reason to discard the measurement. It was left alone
  deliberately. Attributing an error to starvation needs evidence the probe does
  not currently record, unlike the phase maxima above, and the gate can already
  return FAIL without it — in #8277's run, 8 of the 10 probe-bearing reps
  tripped only the degenerate-coroutine rule. Changing it is a separate change
  with its own evidence.
- **Historical `INSUFFICIENT-DATA` cells.** Every one on a concentrated-tail
  fixture is a candidate masked FAIL, including the one reported on #7159 on
  2026-08-31. They were not re-run as part of this change.

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
