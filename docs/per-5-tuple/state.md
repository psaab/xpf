# Per-5-Tuple Fairness Drive — State

**As of 2026-05-09.** This document records the standing mandate, the
shipped foundations, the killed mechanisms, and the surviving design
options for cross-worker per-(dip,dport,sip,sport) fairness on the
xpf userspace AF_XDP dataplane. It is a living state file — update
when issues open, ship, or close. The intent is that the next session
can read this file and inherit a clean working set rather than re-deriving
the history from issue/PR archaeology.

## Standing mandate

Drive per-(dip,dport,sip,sport) fairness end-to-end. The aggregate
fairness target is captured by the structural CoV contract shipped in
PR #1217:

> observed_CoV ≤ Cstruct + 0.05

where `Cstruct` is computed from the per-worker active-flow distribution
`{aᵢ}`, plus a starved-flow hard fail and a saturated-only aggregate gate.

The user accepts aggregate throughput regression on degenerate RSS
distributions if it buys per-flow fairness on the realistic ones.

## Shipped foundations

### PR #1217 — Fairness regimes contract (e1ec6b90, 2026-05-07)

Defines the contract a fairness mechanism must clear:

- structural CoV: `observed_CoV ≤ Cstruct + 0.05`
- starved-flow hard fail: any flow that gets ≤ 1% of mean per-flow
  throughput for the entire steady-state window fails the gate
- saturated-only aggregate gate: the `(observed_aggregate <
  structural_cap × 0.97)` check applies only when the offered load is
  large enough to expect saturation
- structural cap: `(n_active / n_total_workers) × shaper_rate`

Document: `docs/fairness-regimes.md`. Pinned worked examples live in
`userspace-dp/src/fairness.rs::tests`.

### PR #1220 — Fairness harness (bf87cf71, 2026-05-07)

Empirically measures `Cstruct` and `observed_CoV` from a real iperf3
run. Answers the operational question "is observed_CoV at the
structural ceiling, or is there a scheduler bug?"

- BPF-side: `last_used_epoch: u16` on `FlowCacheEntry`, owner-only
  writes on lookup hit; no per-packet hot-path cost.
- Userspace-dp: `count_active_flows()` scans 4096-entry flow_cache
  every ~65 ms (umem 0xFFFF gate, ~15 Hz publish rate); writes
  `BindingLiveState.active_flow_count: AtomicU32`.
- Exposure: `xpf_userspace_binding_active_flow_count{binding_slot,
  queue_id, worker_id, iface}` Prometheus gauge.
- Harness: `test/incus/fairness-harness.sh` runs iperf3 + 1 Hz
  /metrics scrape; `userspace-dp/src/bin/fairness-eval` parses
  iperf3 -J + 6-col TSV, aggregates per-worker on filtered iface,
  emits PASS/FAIL verdict JSON.

Operational measurement (iperf-c P=12 -R, ge-0-0-2): observed_CoV
≈ 47% **is below** the structural ceiling for the RSS distribution
the cluster produced. **No scheduler bug; structurally skew-bound
under that input.** Any fairness mechanism must be evaluated against
this gate, not against an unconditional CoV target.

## Killed designs

Two categories. **Mechanisms** (in-dataplane scheduler / steering /
key changes) are the things the bound below directly speaks to;
**confounds** (test methodology, cluster topology) eliminate
hypothetical alternative explanations of the variance. Both are kept
because both ship signal to a future reader, but they fail in
*different* ways.

### Dataplane mechanisms

| # | Issue | Killed | Reason |
|---|-------|--------|--------|
| 1 | #840 | reverted | runtime NIC RSS indirection-table tuning can't fix cross-binding skew with long-lived flows |
| 2 | #1215 | PLAN-KILL | local-stall mechanism: head-of-line blocking on a single worker doesn't compose across workers |
| 3 | #836 | PLAN-KILL | shared HOL queue: AF_XDP UMEM ownership prevents cross-worker descriptor sharing |
| 4 | #840 / #1203 | PLAN-KILL | RSS steering at AF_XDP-ZC binding time is permanent physics — kernel pins flow→queue at bind |
| 5 | #937 | PLAN-KILL | Cross-queue AF_XDP ZC redirect: kernel `XSKMAP` redirect *exists*, but ZC delivery requires `xs->queue_id == xdp->rxq->queue_index` (`net/xdp/xsk.c::xsk_rcv_check`). Cross-queue ZC needs a copy, defeating ZC. Not a kernel-feature-gap; a fundamental ZC-semantics constraint. |
| 6 | #1211 | PLAN-KILL | Path 2 race-safe AFD overlay: closed 2026-05-07 after 8 Codex rounds + 3 Gemini rounds. PR #1220 empirical PASS on the motivating workload made the design solving a non-existent problem. See `docs/per-5-tuple/path2-archive/CLOSING-RATIONALE.md` for full rationale. |
| 7 | #1236 | PLAN-KILL | v6 global per-flow cap: MQFQ fallback loophole — `cos_queue_min_finish_bucket` falls back to lowest-finish bucket when all over-cap, so the cap is silently ignored. Plan-killed 2026-05-08. |
| 8 | #1237 | PLAN-KILL | v7 reactive-share: causality inversion. A worker at 72% of its share has plenty of headroom; the primary worker's share isn't the one limiting it. Plan-killed 2026-05-08. |
| 9 | #1239 | PLAN-KILL | Surplus-proportional: shrinking-pie math bug. Quota against a shrinking pool strands 25–31% of `class_room` in pathological splits ([4,3,2,3] → 31.25%, [6,5,1] → 26.7%). Plan-killed 2026-05-08. |
| 10 | #1243 | PLAN-KILL | 5-worker dedicated CPU mode: multinomial(12, 5)+uniform vs (12, 6)+skew CoV cancels (~55.5% vs ~55.8%). Zero quantitative gain to justify −17% saturation throughput. Plus single-CPU control-plane VRRP-starvation risk + i40e ethtool-order disagreement between reviewers. Plan-killed 2026-05-08. |
| 11 | #1244 | EMPIRICAL-KILL | RSS Toeplitz auto-tune: direct simulation proved current Microsoft standard key is already at the multinomial floor — see "Multinomial fairness ceiling" below. Empirically killed 2026-05-08. |

### Test-methodology / topology confounds

| # | Issue | Killed | Reason |
|---|-------|--------|--------|
| C1 | #1245 | EMPIRICAL-KILL | Multi-receiver test methodology: 5-sample CoS-off comparison (12 streams to 1 port vs 12 streams across 6 ports each running its own iperf3 -s) showed CoV mean delta 2.2pp (51.7% vs 49.5%) — within sample noise. Receiver-side TCP coupling is NOT the variance source. Confounds-only, not a dataplane-mechanism kill. |

## Multinomial fairness ceiling

After five consecutive kills on distinct in-dataplane fairness
mechanisms (#1236 v6 global cap, #1237 v7 reactive share, #1239
surplus-proportional, #1243 5-worker dedicated CPU, #1244 RSS Toeplitz
auto-tune) the architectural ceiling within AF_XDP UMEM-bound design
is documented below. Any future "let's tune the dataplane scheduler /
NIC parameter for better per-flow CoV" pitch must clear the bar in
"Bar for future fairness pitches" at the end of this section.

### The bound (load-bearing premises)

For a test that opens N TCP flows through K AF_XDP workers (one per
RSS queue), the per-flow rate coefficient of variation is bounded
below by the **multinomial(N, K) sampling variance** under all of the
following premises. **Drop any premise and the bound disappears** —
this is what makes the future-pitch gate non-trivial.

| # | Premise | Why it matters |
|---|---------|----------------|
| 1 | **Random ephemeral source ports** hashed uniformly into RSS queues. | Sets the multinomial draw with `p_w = 1/K`. |
| 2 | **Uniform per-worker capacity** `C_w = C` for every active worker. | Lets `C` cancel in CoV; with heterogeneous capacity the bound is strictly larger. |
| 3 | **Within-worker fair share** — each worker splits its capacity equally across its assigned flows. | Without it, a worker can favor some of its own flows and the formula doesn't apply. |
| 4 | **Work conservation** — workers never idle below their share. | A non-work-conserving scheduler can clip the heaviest flows ("Harrison-Bergeron") and reduce CoV at the cost of aggregate throughput. CoS-on shaping is exactly this case (CoV mean 16.6% on iperf-d, well below the multinomial floor). |
| 5 | **All admitted, no rate-cap** — every flow is served, none rejected or rate-limited. | Same caveat as #4: admission policy can move CoV in either direction. |

Under all five premises, the **population** CoV (matching production
code's `compute_cstruct` and `compute_observed_cov` in
`userspace-dp/src/fairness.rs:24,53`) is bounded below by

```
CoV_floor(N, K) = E_{c ~ Multinomial(N, 1/K)}[ stddev_pop(rates(c)) / mean(rates(c)) ]
```

where `rates(c) = {1/c_w : c_w times for each active worker w}` and
idle workers (`c_w = 0`) are excluded — same convention as the
contract. For **N=12, K=6 the exact closed-form value is 51.06%**
(full enumeration over all multinomial outcomes; matches Monte-Carlo
51.01% ± 0.05pp at n=100,000 trials).

The bound is a function of `(N, K)` and the load-bearing premises,
**not** of the scheduler, hash key, surplus algorithm, lease
implementation, or any other in-dataplane mechanism that preserves
all five premises.

### Empirical confirmation (2026-05-08, refreshed 2026-05-09)

Two checks, with explicit error bars. Both use **population** CoV to
match the production fairness contract.

**(a) Toeplitz hash simulation against premises 1–5.** Python
simulation of the Toeplitz hash on the actual ephemeral port range
(32768–60999) with two candidate keys, mapped through the i40e
128-entry indirection table at `equal 6`. 100,000 trials of "draw 12
random ports, hash each, group by queue, compute per-flow population
CoV":

| Configuration | CoV mean | Gap to floor |
|---------------|----------|--------------|
| Multinomial(12, 6) exact (closed-form) | **51.06%** | — |
| Multinomial(12, 6) Monte Carlo (n=100k) | 51.01% | within 1 SEM (±0.05pp) |
| Microsoft standard Toeplitz key (current) | ≈ 51.0% | within 1 SEM |
| Symmetric Toeplitz key (recipe knob target) | ≈ 51.0% | within 1 SEM |

The previous version of this table reported "+0.07pp" and "+0.33pp"
gaps at n=10,000. Those gaps were below 1 SEM (≈ 0.15pp at that trial
count) and have been removed — displaying a "gap" smaller than the
standard error overclaims precision. The conclusion stands: under the
five premises, neither key choice can move the bound.

**(b) Production cross-check (cautionary).** CoS-off iperf-d
12-stream on the loss userspace cluster: observed population CoV
mean 51.7% (n=5, SEM ≈ ±6.9pp). This is **not** a clean confirmation
of the bound: the production cluster has worker 0 sharing CPU 0 with
the daemon (premise 2 mildly violated, lifting the *true* bound
*above* 51.06%), and n=5 is wide-error-bar territory. Treat the
number as ballpark consistency, not proof.

### What this rules out

Any mechanism that preserves all five load-bearing premises and
accepts the same `(N, K)` and input distribution **cannot** reduce
the **expected** per-flow CoV below the multinomial floor — `51.06%`
for N=12, K=6, premises 1–5. Note this is an expectation over random
port draws: any individual run can be below the floor (e.g. a `(2,
2, 2, 2, 2, 2)` partition gives CoV 0; `P(per-run CoV < 51.06%) ≈
59%` by exact enumeration). What's bounded is the long-run average
across repeated trials. Specifically ruled out under those premises:

- **Better RSS hash key** (#1244 — already at floor).
- **Reducing K from 6 to 5** (#1243 — under population CoV the exact
  uniform floors are K=6: 51.06%, K=5: 51.17% (close, with K=6
  slightly better). #1243's empirical numbers were on heterogeneous
  hardware: K=5 with uniform per-bin capacity produced ~55.5% CoV,
  vs K=6 with one ~70%-capacity bin at ~55.8% — the two effects
  cancel within rounding. The monotonic claim "K-1 is always worse
  than K" is **not generally true** (at K=1, all flows land on one
  worker → uniform per-flow rate → CoV=0; variance is non-monotonic
  in K). What's true for the specific N=12, K=6 → K=5 case on this
  hardware is what #1243 measured: zero net CoV gain.)
- **Per-worker scheduler tuning** (#1236, #1237, #1239 — affects
  within-worker fairness, but multinomial draws *between* workers
  dominate variance under premises 1–5).
- **Cross-queue AF_XDP zero-copy redirect** (#937). Kernel XDP
  redirect to AF_XDP sockets *does* exist (`bpf_redirect_map` +
  `BPF_MAP_TYPE_XSKMAP`, since Linux 4.18). What is physically
  prevented is **cross-queue zero-copy descriptor delivery**: UMEM
  chunks are bound to the RX ring of the queue they were filled on
  (kernel `xsk_rcv_check()` validates `xs->queue_id ==
  xdp->rxq->queue_index` before delivery). Redirecting a ZC frame
  to a socket bound to a different queue requires a copy, which
  defeats the point of zero-copy. Kernel feature work alone cannot
  fix this — it would need a fundamental change in AF_XDP ZC
  semantics.

### What's left in scope

A pitch can move the floor by attacking **any** load-bearing premise.
Recognized levers:

1. **Increase N (more flows).** Population CoV shrinks roughly like
   `1/sqrt(N)`: 10× more flows ≈ √10 ≈ 3.16× CoV reduction. Test
   methodology, not dataplane.
2. **Change the input distribution (premise 1).** Random ephemeral
   ports give the uniform-multinomial bound. **Sequential / fixed
   source ports** could in principle be deterministically routed into
   evenly-spread bins. #1233 (sender-side TCP head-start) is in this
   category; ports stay random but cwnd asymmetry is fixed at the
   sender, not at the firewall.
3. **Increase K with proportional capacity.** Limited by physical
   CPUs and per-binding capacity. The catch from #1243: changing K
   alone trades aggregate throughput for fairness without net
   benefit; only K *plus* added physical capacity (more cores or
   higher per-queue throughput) moves the floor without #1243's
   cancellation.
4. **Asymmetric routing probability** (premise 1, sub-attack). Tune
   the RSS indirection table so `p_w ≠ 1/K` — under-weight the
   CPU-shared worker (e.g. worker 0 alongside the daemon) and
   over-weight the others. Restores premise 2 effectively, even
   though physical capacities differ. **Not yet attempted.**
5. **Heterogeneous-aware scheduler** (premise 3, sub-attack). If
   workers cooperate to fair-share a *global* per-flow allocation
   (rather than each fair-sharing locally), the within-worker
   premise breaks and the bound no longer applies. The known
   blockers are AF_XDP ZC physics (queue-ownership: see #836, #937,
   #1215) and the per-flow rate equality / work conservation /
   no-Harrison-Bergeron trilemma: any global-fair scheme has to give
   up at least one of them, and the four prior mechanism kills
   (#1236, #1237, #1239, #1243) each found a different way to prove
   that.
6. **Non-work-conserving / shaped (premise 4 / 5).** CoS-on iperf-d
   12-stream CoV mean is 16.6%, well below the 51% multinomial
   floor — because shapers clip each flow's rate, dragging the
   distribution toward the shaped value. The fairness contract
   already accommodates this: `Cstruct` is computed from `{aᵢ}`,
   not from a fixed CoV.

### Bar for future fairness pitches

Any new fairness issue that targets per-flow CoV reduction on the
12-stream test workload must, at plan v1:

1. **Name the bound input being changed** — one or more of: the
   parameters `N` or `K`, or one or more of the five load-bearing
   premises in the bound table. Pitches that change none of these
   cannot move the floor — they should not be plan-reviewed.
2. **Quantify the expected CoV reduction** against the bound *under
   the new premise*. ("Reduces CoV from 51% to X% by attacking
   premise 1 with asymmetric `p_w`" is fine. "Reduces CoV by
   improving the scheduler" without naming a premise is the
   sixth-attempt repeat of #1236/#1237/#1239/#1243/#1244.)
3. **Show the math first.** Include a Python simulation or
   closed-form calculation of the new bound *before* proposing
   implementation.

If the pitch can't clear (1) and (2), close at plan time.

## Surviving design options

### Path 2: race-safe AFD overlay (#1211) — CLOSED 2026-05-07

**Status**: PLAN-KILL. Issue #1211 closed 2026-05-07 after 8 Codex
rounds + 3 Gemini rounds. v10 round added the empirical merge bar
from PR #1220, and both reviewers converged on stop-the-prototype:
Gemini explicit PLAN-KILL ("v10 successfully uses empirical data to
prove its own irrelevance"), Codex tighten-the-gate-and-pause-until-
failing-workload-exists. PR #1220's PASS verdict on the motivating
workload made the AFD design solving a non-existent problem.

**Archive**: see `docs/per-5-tuple/path2-archive/` for the v10 plan
(with full v2-v9 review history inline) plus a CLOSING-RATIONALE.md
covering when to revisit and how NOT to revisit. **Do not re-open
#1211 with new arguments** — start a fresh issue if any of the
revisit criteria fire.

### Path 4: workload-aware gate

**Status**: not yet captured in an issue. Concept is to gate the
harness's verdict on the workload class rather than blindly applying
the CoV+0.05 contract — e.g. for trivially-skewed RSS (one worker has
all flows), the contract correctly returns PASS because Cstruct is
already large; for balanced RSS the contract correctly demands tight
CoV. The harness already does this implicitly via `Cstruct`. What's
missing is an *operational* gate: the firewall config should be
allowed to declare "I expect balanced RSS and want to be paged on
structural skew" — a declarative fairness expectation that gets
checked at runtime, not just in test.

If pursued, this is a smaller-than-Path-2 swing and pure userspace.

## Open work

- **#547 — Deterministic RSS-skew test fixture**: SHIPPED as PR #1223
  (92b3b62d, 2026-05-07). 7 black-box integration tests pin the
  `fairness-eval` binary's CLI/IO/exit-code contract.
- **#1224 — Harness sum-guard sensitivity at low N**: filed
  2026-05-07 from the empirical sweep below. P=2 toggles between
  PASS and Guard FAIL depending on RSS placement; tolerance floor
  `GUARD_ABSOLUTE = 2` is too tight at small expected_sum. Small
  follow-up; not a fairness mechanism.
- **#1211 follow-up (only if gate flips to FAIL on a real workload)**:
  open a fresh issue using the revisit criteria in the Path 2
  closure archive. Do not re-open #1211 directly. As of the
  2026-05-07 sweep below, NO empirically failing workload exists.
- **Path 4** has no issue and per the empirical sweep no concrete
  motivation. Consider filing only if a workload-aware gate
  becomes operationally desirable.

## Empirical sweep across workload classes (2026-05-07)

After PR #1220 (harness) and #1223 (fixture) shipped, the harness
was run end-to-end on the loss userspace cluster across the 4
workload classes Codex round-1 enumerated for #1211 v10 (P-class
sweep × push/reverse × CoS-default). Cluster: master commit
92b3b62d. Method: iperf3 -P N -t 90 from `loss:cluster-userspace-host`
to 172.16.80.200; 1Hz `xpf_userspace_binding_active_flow_count`
scrape from firewall via incus exec; fed to `fairness-eval --iface
ge-0-0-2 --n-workers 6 --warmup-secs 5 --final-burst-secs 1
--shaper-rate-bps 25e9`.

| Workload | cstruct | observed_cov | gap | starved | guard | verdict |
|----------|---------|--------------|-----|---------|-------|---------|
| P=12 -R (canonical) | 0.63 | 0.54 | -0.09 | 0 | OK | **PASS** |
| P=2 -R | 0.0–0.65 | ~0.03 | varies | 0 | flaky | flaky |
| P=6 -R | 0.28 | 0.27 | -0.01 | 0 | OK | **PASS** |
| P=24 -R | 0.21 | 0.18 | -0.03 | 0 | OK | **PASS** |
| P=12 push | 0.49 | 0.45 | -0.04 | 0 | OK | **PASS** |

**Key findings**:

1. **No Gate 1 (starvation) or Gate 2 (CoV gap > ε) FAIL** on any
   workload class. Every PASS verdict has gap well below ε=0.05.
2. **PUSH and REVERSE differ structurally.** P=12 push has
   cstruct=0.49 while P=12 reverse cstruct=0.63 — different RSS
   distributions for the two TX-direction binding sets. Both PASS
   independently.
3. **n_active varies with P.** P=2 → 3 active workers (RSS
   spread); P=6 → 6; P=12 → 5; P=24 → 6.
4. **Harness sum-guard is flaky at P=2** (filed as #1224). Not an
   AFD justification; a small harness tolerance fix.
5. **#1211 PLAN-KILL stands.** No workload tested produces an
   AFD-actionable FAIL. The drive's empirical premise — that the
   harness PASSes the production workloads — extends beyond the
   canonical iperf-c P=12 -R measurement.

## How to apply

When considering a new fairness mechanism:

1. Read `docs/fairness-regimes.md` (the contract).
2. Run the harness on the loss userspace cluster against the current
   master to capture the baseline `(observed_CoV, Cstruct, gap)` for
   the targeted workload (e.g. iperf-c P=12 -R, ge-0-0-2).
3. Plan the mechanism with the gate baked in: "must reduce
   observed_CoV by at least Δ on workload X without regressing
   workload Y".
4. Triple-review the plan (Codex hostile + Gemini adversarial + this
   doc as architectural prior).
5. Bench against the harness, not against ad-hoc one-off
   measurements. The harness's verdict is the merge bar.

## Change log

- 2026-05-07: doc created; PR #1220 merged (harness shipped). Path 2
  v9 plan in flight; #547 deterministic fixture pending.
- 2026-05-07 (later): #1211 Path 2 CLOSED as PLAN-KILL after v10
  reviewer convergence. Archived under `path2-archive/`. #547 v2 in
  flight after Codex MAJOR rewrite.
- 2026-05-07 (end of day): PR #1223 #547 fixture MERGED. Empirical
  4-workload-class sweep performed; no Gate 1/2 FAIL. #1224 filed
  for a low-N harness sensitivity nit. **The per-5-tuple drive's
  standalone foundations are now empirically settled.** Future
  fairness-mechanism work should start with: (a) read this doc;
  (b) re-measure the harness against the targeted workload; (c)
  if it FAILs, file a fresh issue citing #1217+#1220+the sweep
  table above; (d) if it PASSes, the drive remains empirically
  closed and a new mechanism is solving a non-existent problem.
- 2026-05-08: Five consecutive kills on dataplane-only fairness
  mechanisms documented (#1236 v6 global cap, #1237 v7 reactive
  share, #1239 surplus-proportional, #1243 5-worker dedicated CPU,
  #1244 RSS Toeplitz auto-tune empirical kill). #1244 empirically
  killed via direct simulation: current Microsoft standard key sits
  at the multinomial(12, 6) floor. The multinomial fairness ceiling
  is now the project's formal prior; see "## Multinomial fairness
  ceiling" above. Future fairness pitches must clear the bar stated
  there at plan v1 — name the load-bearing premise being attacked,
  quantify the new bound, simulate before implementing. (The
  original write-up landed in PR #1246 with sample CoV and three
  premises; corrected by the 2026-05-09 follow-up below.)
  - #1245 (test-methodology kill, separate from the five mechanism
    kills): multi-receiver comparison showed 2.2pp CoV delta
    (51.7% vs 49.5%) — within sample noise; receiver-side TCP
    coupling ruled out as a variance source.
- 2026-05-09: Retroactive triple-review of PR #1246 (the original
  ceiling write-up) returned NEEDS-FOLLOWUP-MAJOR from both Codex
  and Gemini Pro 3. Follow-up PR fixes:
  (a) Restated the bound under five explicit load-bearing premises
      (random ports, uniform capacity, within-worker fair share,
      work conservation, all-admitted) — the original framing
      omitted work conservation and admission, which made
      "scheduler X cannot beat the floor" overclaim.
  (b) Switched the metric from sample CoV to **population** CoV,
      matching production `compute_cstruct` and `compute_observed_cov`
      in `userspace-dp/src/fairness.rs`. The exact closed-form floor
      for N=12, K=6 under population CoV is **51.06%** (was 53.17%
      with sample CoV, which doesn't match the contract).
  (c) Removed the false-precision +0.07pp / +0.33pp gaps in the
      empirical table — at n=10,000 those gaps were below 1 SEM
      (≈ 0.15pp). Reran simulation at n=100,000 (SEM ≈ 0.05pp); both
      keys are at the floor.
  (d) Demoted the production CoS-off cross-check from "confirmation"
      to "ballpark consistency" — the cluster mildly violates premise
      2 (worker 0 shares CPU 0 with daemon) and n=5 has SEM ≈ 6.9pp.
  (e) Rewrote the #937 row: kernel `XSKMAP` redirect *exists* (since
      Linux 4.18); what's prevented is cross-queue ZC delivery
      (`xs->queue_id == xdp->rxq->queue_index` check in
      `net/xdp/xsk.c::xsk_rcv_check`). Original "kernel feature
      doesn't exist" framing was wrong.
  (f) Expanded the future-pitch gate from three premises (N / K /
      input distribution) to all five load-bearing premises, making
      legitimate attacks like asymmetric `p_w` (premise 1 sub-attack)
      and heterogeneous-aware scheduling (premise 3) admissible.
  (g) Split the killed-designs table into "dataplane mechanisms"
      and "test-methodology / topology confounds" so the "five
      consecutive mechanism kills" framing maps cleanly to what's
      actually in the table.
