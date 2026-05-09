# Per-5-Tuple Fairness Drive — State

**As of 2026-05-07.** This document records the standing mandate, the
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

## Killed mechanisms

| # | Issue | Killed | Reason |
|---|-------|--------|--------|
| 1 | #840 | reverted | runtime NIC RSS indirection-table tuning can't fix cross-binding skew with long-lived flows |
| 2 | #1215 | PLAN-KILL | local-stall mechanism: head-of-line blocking on a single worker doesn't compose across workers |
| 3 | #836 | PLAN-KILL | shared HOL queue: AF_XDP UMEM ownership prevents cross-worker descriptor sharing |
| 4 | #840 / #1203 | PLAN-KILL | RSS steering at AF_XDP-ZC binding time is permanent physics — kernel pins flow→queue at bind |
| 5 | #937 | PLAN-KILL | ingress XDP_REDIRECT for fairness: kernel feature support not present, would need upstream work |
| 6 | #1211 | PLAN-KILL | Path 2 race-safe AFD overlay: closed 2026-05-07 after 8 Codex rounds + 3 Gemini rounds. PR #1220 empirical PASS on the motivating workload made the design solving a non-existent problem. See `docs/per-5-tuple/path2-archive/CLOSING-RATIONALE.md` for full rationale. |
| 7 | #1236 | PLAN-KILL | v6 global per-flow cap: MQFQ fallback loophole — `cos_queue_min_finish_bucket` falls back to lowest-finish bucket when all over-cap, so the cap is silently ignored. Plan-killed 2026-05-08. |
| 8 | #1237 | PLAN-KILL | v7 reactive-share: causality inversion. A worker at 72% of its share has plenty of headroom; the primary worker's share isn't the one limiting it. Plan-killed 2026-05-08. |
| 9 | #1239 | PLAN-KILL | Surplus-proportional: shrinking-pie math bug. Quota against a shrinking pool strands 25-31% of `class_room` in pathological splits ([4,3,2,3] → 31.25%, [6,5,1] → 26.7%). Plan-killed 2026-05-08. |
| 10 | #1243 | PLAN-KILL | 5-worker dedicated CPU mode: multinomial(12, 5)+uniform vs (12, 6)+skew CoV cancels exactly (~55.5% vs ~55.8%). Zero quantitative gain to justify -17% saturation throughput. Plus single-CPU control-plane VRRP-starvation risk + i40e ethtool-order disagreement between reviewers. Plan-killed 2026-05-08. |
| 11 | #1244 | EMPIRICAL-KILL | RSS Toeplitz auto-tune: direct simulation proved current Microsoft standard key is **already at the multinomial floor** — see `## Multinomial fairness ceiling` below. Empirically killed 2026-05-08, no triple-review needed. |
| 12 | #1245 | EMPIRICAL-KILL | Multi-receiver test methodology: 5-sample CoS-off comparison (12 streams to 1 port vs 12 streams across 6 ports each running its own iperf3 -s) showed CoV mean delta of 2.2pp (51.7% vs 49.5%) — within sample noise. Receiver-side TCP coupling is NOT the variance source. Test-methodology kill, not a dataplane-mechanism kill. |

The table above is the current canonical triage for killed mechanisms
and reviewer findings.

## Multinomial fairness ceiling

After five consecutive kills (#1236, #1237, #1239, #1243, #1244) on
distinct dataplane-only fairness mechanisms, the architectural ceiling
within AF_XDP UMEM-bound design is now empirically confirmed. Any
future "let's tune the dataplane scheduler / NIC parameter for better
per-flow CoV" pitch must clear this bar:

### The bound

For a test that opens N TCP flows from one source to one destination
through K AF_XDP workers (one per RSS queue), with random ephemeral
source ports drawn uniformly from the Linux ephemeral range, and with
within-worker fairness already perfect (each worker shares its
capacity equally across its assigned flows), the per-flow rate
coefficient of variation is bounded below by the **multinomial(N, K)
sampling variance**:

```
CoV_floor(N, K) = E[stdev(rate_i) / mean(rate_i)]
```

where `rate_i = 1/count_i` for flow `i` in a queue with `count_i`
flows, and `(count_1, ..., count_K) ~ Multinomial(N, 1/K, ..., 1/K)`.

For fixed N and K this bound has nothing to do with the scheduler,
the hash key choice, the surplus algorithm, or the lease
implementation. It comes from the **statistics of throwing N balls
into K bins** — the probability that any single trial lands a ball in
bin `i` is `1/K`, giving a Bin(N, 1/K) marginal per bin and a
standard deviation of `sqrt(N (K-1) / K²)` for each bin's count.
Changing N or K changes the bound; changing any scheduler or hash
detail within fixed N and K cannot.

### Empirical confirmation (2026-05-08)

Direct Python simulation of the Toeplitz hash on the actual ephemeral
port range (32768-60999) with two candidate keys, mapped through the
i40e 128-entry indirection table at `equal 6`. 10,000 trials of
"draw 12 random ports, hash each, group by queue, compute per-flow
rate CoV":

| Configuration | CoV mean | CoV stdev | Gap to floor |
|---------------|----------|-----------|--------------|
| Multinomial(12, 6) theoretical floor | **53.2%** | 15.5% | — |
| Microsoft standard Toeplitz key (current) | 53.2% | 15.3% | +0.1pp |
| Symmetric Toeplitz key (recipe knob target) | 53.5% | 15.2% | +0.3pp |

The current key is statistically indistinguishable from a perfect
uniform hash. Cross-check against production CoS-off iperf-d 12-stream
measured CoV: 51.7% mean (5 samples) — within sampling noise of the
53.2% theoretical floor.

### What this rules out

Any mechanism that operates entirely within the AF_XDP UMEM-bound
dataplane and accepts the same flow input distribution **cannot**
reduce the 12-flow per-run CoV mean below ~53% in the unshaped case.
Specifically ruled out by the bound:

- **Better RSS hash key** (#1244 — already at floor)
- **Reducing worker count** (#1243 — multinomial(N, K-1) is *worse*
  than multinomial(N, K) for fixed N; the current K=6 was chosen
  because it is already optimal for this hardware. Adding workers
  beyond the current K is a different premise — see "Increase K"
  below.)
- **Per-worker scheduler tuning** (#1236, #1237, #1239 — affects
  within-worker fairness, but multinomial draws *between* workers
  dominate variance)
- **Cross-worker ingress redirect** (#937 — requires kernel
  XDP_REDIRECT support that doesn't exist; even if it did, the
  AF_XDP UMEM-ownership physics prevents the descriptor sharing
  the design requires)

### What's left in scope

Only attacks that change the bound's *premises* can move the floor:

1. **Increase N (more flows).** Multinomial variance shrinks like
   `1/sqrt(N)`. A 120-flow test has ~3.2× lower expected CoV than a
   12-flow test (sqrt(10) ≈ 3.16). Test methodology, not dataplane.
2. **Change the input distribution.** Random ephemeral ports give
   the multinomial bound. **Sequential ports / fixed source ports**
   could in principle be hashed deterministically into evenly-spread
   bins. #1233 (sender-side TCP head-start) is in this category;
   ports are still random but cwnd asymmetry is fixed at sender,
   not at firewall. Workload-side change.
3. **Increase K (more workers).** Limited by physical CPUs and by
   each worker's per-binding capacity. Trades aggregate throughput
   for fairness — see #1243's tradeoff for why the current K=6 was
   already chosen optimally for this hardware.
4. **Accept the ceiling and clip with shaping.** CoS-on iperf-d
   12-stream CoV mean is 16.6% — far below the 53% multinomial
   floor — because shapers cap each flow's rate, dragging the
   distribution toward the shaped value. The fairness contract
   already accommodates this: `Cstruct` is computed from `{aᵢ}`,
   not from a fixed CoV.

### Bar for future fairness pitches

Any new fairness issue that targets per-flow CoV reduction on the
12-stream test workload must, at plan v1:

1. State explicitly which premise of the multinomial bound it is
   attacking (N, K, or the input distribution).
2. Quantify the expected CoV reduction against the multinomial floor
   for the *new* premise. ("Reduces CoV from 53% to X% by changing
   N from 12 to 120" is fine. "Reduces CoV by improving the
   scheduler" is not — that's what the five killed mechanisms
   already tried.)
3. Include a Python simulation or back-of-envelope calculation
   showing the new bound BEFORE proposing implementation.

If the pitch can't clear (1) and (2), it's a sixth-attempt repeat of
the same dead-end. Close at plan time.

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
  at the multinomial(12, 6) floor (53.2% empirical vs 53.2%
  theoretical, +0.1pp gap). The multinomial fairness ceiling is now
  the project's formal prior; see "## Multinomial fairness ceiling"
  above. Future fairness pitches must clear the bar stated there at
  plan v1 — name the premise being attacked (N, K, or input
  distribution), quantify the new bound, simulate before
  implementing.
