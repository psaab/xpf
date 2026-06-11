# #1863 — CoS guarantee-rate honored-realization gap: ceiling-math kill-exit + H1 mechanism attribution

- **Revision:** v1 (round 1)
- **Date:** 2026-06-11
- **Branch:** `research/1863-realization-gap`
- **Mode:** /research — no production code; measurement + code-trace evidence
- **Measured target:** loss userspace cluster; build content-identical to
  master `6d8fa810d` (deployed `…2195-gaff208a18`; `git rev-parse
  6d8fa810d^{tree} == aff208a18^{tree} == 78ff3087…` — verified before the
  cells); fixture `test/incus/cos-iperf-config.set` (shaping-rate 25g,
  `oversubscription-policy guarantee-rate 0.7`, equal-flow default-OFF,
  verified in the active config in-band)

## 1. Problem statement

#1863 inherits exactly one question from the #1614 close (Reading-B
residual): Phase-1-honored mid classes (3g/6g) realize only ~70-71% of
shape under a Phase-2 aggressor (24g) vs 88-91% with the aggressor
absent — a ~16-19 pt honored-realization gap, monotone in `R_i`. The
issue carries a ratified PLAN-KILL exit: if the gap is explained by
physical-ceiling division ("unshaped-mix-ceiling"), close as physics.

This round answers, in order:
1. **KILL-exit first**: does ceiling division (C_phys ≈ 22.6 G over the
   measured class mix) predict the observed realization? (§3)
2. If not: does the code-located H1 (stable-quantum charge +
   once-per-epoch honored lockout + token-clamped send, fueled by the
   v8 lease) survive quantitative confrontation with per-queue
   counters? What exactly bounds the realized bytes? (§4-§5)
3. Perturbation cells that move the parameter H1 says matters. (§6)

## 2. Measurement evidence (section of record)

All cells: loss cluster, push direction, client
`loss:cluster-userspace-host` → 172.16.80.200, 12 streams/class, 30 s
TCP, serialized under `/tmp/xpf-cluster.lock`, runner `run-cell.sh`
(archived alongside; same harness as the 1614 corpus). Raw iperf3 JSON
+ full before/after `/metrics` snapshots under `raw/`. Snapshots taken
on the RG0-primary node (fw1 this session); CoS runtime location
verified per-cell via nonzero counter deltas.

### 2.1 Baseline re-anchor on current master (small4+24g, 2 reps)

| Class | shape | r1 %shape | r2 %shape | 1614 corpus mean (9 reps, `aa6fa6fc8`) |
|-------|-------|-----------|-----------|---------------------------|
| 100m | 0.1G | 93.5 | 93.9 | 94.2 |
| 1g | 1.0G | 87.4 | 87.0 | 88.4 |
| **3g** | 3.0G | **68.9** | **73.1** | **71.1** |
| **6g** | 6.0G | **66.4** | **70.8** | **70.0** |
| 24g | 24.0G | 43.3 | 50.4 | 49.1 |
| SUM | | 17.41G | 19.51G | 18.7-19.5G |

The #1614 decisive-cell phenomenon reproduces unchanged on current
master content (#1867 equal-flow knob merged since, default-OFF — no
behavioral delta, as designed).

### 2.2 Aggressor-rate sweep (config-free: aggressor = port choice)

small4 + ONE aggressor class, aggressor ∈ {9g, 12g, 24g}; 2 reps each.
Total offered demand (Σ shapes) and aggregate delivered:

| Cell | Σ demand | delivered (r1/r2) | 3g %shape | 6g %shape | aggressor %shape |
|------|----------|----------------|-----------|-----------|------------------|
| small4 alone (1614 §2.3) | 10.1G | 9.0/9.2G | 87.5-91.5 | 88.7-91.1 | — |
| +9g | **19.1G** | **15.2/15.1G** | 81.4/80.1 | 81.3/81.9 | 76.9/76.5 |
| +12g | 22.1G | 15.4/16.8G | 77.9/79.5 | 74.6/78.9 | 63.6/73.0 |
| +24g | 34.1G | 17.4/19.5G | 68.9/73.1 | 66.4/70.8 | 43.3/50.4 |

**The +9g row is the kill-exit refutation cell** (§3): total demand
19.1 G is ~3.5 G BELOW the measured C_phys ≈ 22.6 G (1614 §2.1
solo-uncapped), yet the system delivers only 15.1-15.2 G — ~4 G of
demanded, in-shape bandwidth is left undelivered, and every class
(including the aggressor itself) sits below shape. Ceiling division
cannot produce this: there is no ceiling to divide at 15 G.

Also note: the mid-class gap is **monotone in aggressor rate at fixed
regime** (all three aggressor cells have the aggressor Phase-2-active;
§2.3): 81% → 78% → 70%. Any pure regime-flip story (honored vs not)
fails this monotonicity; H1' (§5) explains it via selector-cadence and
lease-pressure scaling.

### 2.3 Per-queue counter deltas (decisive discriminators)

From the per-cell `/metrics` deltas (counters summed across the 6
workers; B/honor = `drain_guarantee_sent_bytes / (phase1+phase2
admissions)`; honor interval = 30 s × 6 workers / admissions):

small4+24g (base-r2) vs small4-ALONE (1614 corpus r1, same build
content):

| Queue | cell | p1 adm | p2 adm | sent GB | B/honor | mean honor interval/worker |
|-------|------|--------|--------|---------|---------|-----------------------------|
| 3g | +24g | 492,093 | 0 | 8.63 | 17,539 | 366 µs |
| 3g | alone | 533,364 | 0 | 10.80 | 20,241 | 338 µs |
| 6g | +24g | 491,971 | 0 | 16.73 | 34,012 | 366 µs |
| 6g | alone | 813,070 | 0 | 21.49 | 26,434 | 221 µs |
| 24g | +24g | 0 | 717,540 | 47.63 | 66,379 | — |

Waterfill epoch counter (`waterfill_epochs_total`, per-interface,
all-worker sum; mean worker-epoch = 180 s / Σ):

| Cell | epochs (30 s) | mean worker-epoch |
|------|---------------|-------------------|
| small4 alone | 3,722,628 | **48 µs** |
| +9g | 2,421,300 | 74 µs |
| +12g | 1,946,638 | 92 µs |
| +24g (r2) | 1,304,362 | **138 µs** |

#1847 undergrant causes (per run): `share_exhausted` 2.0M (+24g),
3.5M (+12g), 4.4M (+9g); `class_cap` 17-22K; others ≤ 18K.

Readings used in §4-§5:
- **Alone, epochs turn over every ~48 µs** — when Phase 2 finds
  nothing to serve, the wrap path re-arms immediately, so a small
  queue that missed its honor retries within tens of µs. The
  once-per-epoch lockout is NOT binding without an aggressor.
- **With a backlogged Phase-2 aggressor, epochs stretch toward the
  200 µs time tick** (138 µs mean = mix of time-driven epochs and
  residual wraps) and the honored classes' service cadence collapses
  to ~366 µs/worker (6g: 221 → 366 µs, −40% honors). The lockout IS
  binding: one service opportunity per epoch, misses unrecoverable
  within the epoch.
- **B/honor is small and rate-DECOUPLED**: 3g ~17 K, 6g ~26-34 K —
  nowhere near the honored quanta (75 K / 150 K). §4 derives why:
  the v8-lease top-up watermark is ~32,768 B for every class in this
  fixture, independent of `R_i`.

## 3. KILL-exit analysis: unshaped-mix-ceiling — REFUTED (arithmetic + empirical)

**Arithmetic.** Divide C_phys = 22.6 G (1614 §2.1 solo-uncapped pin;
multi-class aggregates 21.6-24.96 G per #1691) over the small4+24g
demand vector {0.1, 1, 3, 6, 24}:
- Per-class water-fill: level λ with Σ min(R_i, λ) = 22.6 → all four
  small/mid classes saturate at FULL shape, 24g gets the residual
  12.5 G (52%). Prediction: 3g/6g ≈ 94% (their solo health), 24g ≈
  52%.
- Per-stream fair share (60 streams): λ = 1.04 G/stream → every class
  except 24g fully satisfied; same prediction.

Observed: 24g 49.1% ≈ the ceiling-division prediction — but 3g/6g at
70-71% vs predicted ~94%. **No division of a 22.6 G ceiling predicts
the mid-class realization.** The only ceiling-shaped escape is a
mix-specific C_phys ≈ 19 G (15% below the measured solo-uncapped pin).

**Empirical (closes the escape).** The §2.2 +9g cell: demand 19.1 G,
delivered 15.2 G, all classes below shape, mids at 81%. A
ceiling-division explanation requires C_phys(mix) ≈ 15 G for a 5-class
60-stream mix — 33% below the single-class measurement and below the
+24g cell's OWN delivered aggregate (19.5 G, same hardware, same
minute). The undergrant therefore scales with scheduler pressure, not
with proximity to a physical ceiling: aggregates of 15.1, 16.8, 19.5 G
across the sweep are ordered OPPOSITE to ceiling-division (more demand
→ MORE delivered), which no fixed ceiling produces.

A direct unshaped-mix C_phys measurement (same 60-stream port mix, CoS
deleted) is still scheduled (§6 cell U) to BOUND the recoverable
headroom for the fix's acceptance gates — but it can no longer rescue
the kill-exit: even if C_phys(mix) < 22.6 G, the +9g cell already
shows ~4 G undelivered at demand far below any candidate value.

**Disposition: PLAN-KILL exit not taken.** The gap is a scheduler
property, not ceiling arithmetic.

## 4. Code-grounded mechanism (worked trace, all sites on master content)

Sites (`userspace-dp/src/afxdp/cos/queue_service/mod.rs` unless noted):

1. **Per-epoch honor lockout**: `select_exact_cos_guarantee_queue_waterfill`
   charges the STABLE quantum (`phase1_cost =
   cos_guarantee_quantum_bytes(queue).max(head_len)`, :1048) and sets
   the honored bit (:1078-1079), which excludes the queue from BOTH
   phases for the rest of the epoch (:938 Phase 1, :1126-1133 Phase 2).
   The bit clears only on a genuine epoch boundary: the 200 µs time
   tick or a Phase-2 wrap (:896-898).
2. **Epoch turnover regime is aggressor-controlled**: with no Phase-2
   backlog the wrap fires immediately after the smalls are honored
   (alone: 48 µs epochs, §2.3) — lockout harmless. With a backlogged
   Phase-2 class the wrap almost never fires; epochs become
   time-driven (→200 µs) and each honored class gets ONE
   token-clamped service opportunity per epoch per worker.
3. **Per-visit service is watermark-bounded, and the watermark is
   rate-INDEPENDENT in this fixture.** The send budget is
   `queue.hot.tokens.min(visit_cap).max(head_len)` (:1049-1053);
   tokens are fueled only by `maybe_top_up_cos_queue_lease`
   (`cos/token_bucket.rs:206`), whose exact-queue top-up target is
   `lease.lease_bytes().max(COS_EXACT_QUEUE_LEASE_BANK_BYTES).max(frame)
   .min(buffer.max(96 K))` (:248-252). The lease's `lease_bytes` is
   computed by `compute_shared_cos_lease_config_with_bank`
   (`types/shared_cos_lease/mod.rs:876`): `clamp(R_i × 200 µs, 1500,
   lease_ceiling)` where **`lease_ceiling = burst/8`** (:888-894) and
   the queue-lease `burst = queue.buffer_bytes.max(96 K)`
   (`coordinator/mod.rs:1573`). For every class without a configured
   `buffer-size` (3g, 6g, 24g here): burst = 96 K → ceiling = **12 K**
   → `lease_bytes` = 12 K regardless of rate → top-up watermark =
   bank floor = **32,768 B** (8 × 4096, `COS_EXACT_QUEUE_LEASE_BANK_BYTES`).
   1g (buffer 4m) and 100m (500k) also land at the 32 K bank floor
   (their `R_i × 200 µs` is below it).
   **Consequence: the honored quanta 75 K (3g) / 150 K (6g) are
   per-visit UNREACHABLE** — the selector "honors" a 150 K share the
   token plumbing cannot deliver in one visit.
4. **Per-lease-epoch share rationing**: `acquire_v8_with_cause`
   (`shared_cos_lease/mod.rs:1304`) bounds each top-up by the
   per-worker share `cap × my_flows / total_flows` published at
   rotation (`rotate_epoch_v8.rs:350-356`); strict mode deliberately
   does NOT let a worker claim peer slack (:1486-1490 comment).
   Un-acquired share evaporates at rotation (no per-worker carry; the
   carry logic at `rotate_epoch_v8.rs:137-218` only compensates
   rotation LAG). `share_exhausted` 2-4.4M/run (§2.3) is this bound
   firing.
5. **Asymmetric stale-token amplifier for the aggressor**: queue
   tokens are debited at TX COMPLETION
   (`cos/tx_completion.rs`, `apply_cos_prepared_result` path), not at
   selection. Back-to-back Phase-2 admissions (the aggressor is
   admitted on essentially every selector call, §2.3: phase2 ==
   budget_breaks) read not-yet-debited token state, letting its
   per-admission bytes reach ~2× the watermark (observed 66,379 ≈
   2 × 32,768 + ε). Honored classes are lockout-spaced ≥ one epoch
   apart, so completions always settle in between — they never get
   this amplification. (Open question Q1, §9, asks reviewers to
   hostile-check this attribution.)

### Quantitative confrontation (predicted vs observed)

Realized_i ≈ Σ_w min(watermark, share-accrual over honor interval) /
honor-interval, watermark = 32,768 B:

| Class | binding bound | predicted | observed (base-r2 / corpus) |
|-------|---------------|-----------|------------------------------|
| 6g (+24g) | watermark: 32,768 B per 366 µs × 6 workers | 4.30 G (71.6%) | 4.25 G / 70.0% mean |
| 6g (alone) | accrual ~26 K per 221 µs × 6 | 5.7 G (95%) → minus stranding | 5.37-5.46 G (89-91%) |
| 3g (+24g) | share accrual ~22.9 K/interval, minus stranding (share_exhausted) | ≤ 2.8 G; observed-stranding ~25% → ~2.2 G | 2.19-2.30 G (69-73%) |
| 1g (+24g) | accrual 32 K ≥ demand at cadence | ~solo health | 87-88% |
| 100m | unconstrained at any cadence | solo health | 93.5-94.7% |
| 24g | 2× watermark × selector-call rate | ~66 K × 22-24 K/s ≈ 11.7-12.7 G | 10.4-12.1 G |

Four classes × three aggressor levels fit a one-parameter family (the
honor interval, measured independently from `phase1_admissions`). The
issue's H1 is **CONFIRMED in refined form** (H1'):

> The realization gap = (once-per-epoch honored lockout under a
> backlogged Phase-2 aggressor, which pins service opportunities to
> ~1 per stretched epoch per worker) × (a per-visit token ceiling of
> ~32 KB that is RATE-INDEPENDENT because the queue-lease
> `lease_ceiling = burst/8` clamp discards the configured rate for
> every default-buffer class) × (per-lease-epoch share evaporation
> under flow-skew). The Phase-1 "honor" accounting (stable-quantum
> charge) is correct and NOT the defect — the defect is that the
> token plumbing cannot physically deliver the honored quantum within
> an epoch, and the schedule gives no second chance.

What this adjudicates from the issue text: "honored bytes" are
over-promised per-visit by construction (75 K/150 K quanta vs 32 K
deliverable); `share_exhausted` dominance is real but is the
SECONDARY bound for 6g (watermark binds first) and the PRIMARY bound
for 3g.

## 5. Paths

### Path A — mechanism fix (RECOMMENDED for /engineer)

Two independent, individually-testable changes (either alone recovers
part of the gap; together they target the small4-alone level):

- **A1 — rate-aware queue-lease watermark.** Remove/raise the
  `burst/8` ceiling for QUEUE leases so `lease_bytes =
  (R_i × 200 µs).max(bank).min(buffer-scaled cap)` — the honored
  quantum becomes per-visit deliverable. The `burst/8` clamp predates
  the #1630 bank floor and is the right shape for the ROOT lease
  (where burst is the interface burst pool) but, for queue leases,
  burst is just `buffer_bytes.max(96 K)` and the /8 clamp silently
  discards the configured rate. Risk: larger per-visit bursts →
  shaper micro-burstiness; bounded by `visit_cap` (256 K) and the
  root token gate. Hunk-B constraint respected: the HONOR charge
  stays the stable quantum; only the deliverable bytes rise.
- **A2 — epoch-remainder re-eligibility.** When an honored queue's
  visit sent < its charged quantum (token shortfall at visit time),
  allow ONE re-honor within the same epoch for the remainder once
  tokens refill (clear its bit on a token-refill event, or track a
  per-epoch remainder). Restores intra-epoch catch-up that the alone
  regime gets for free via fast wraps. Design constraints carried
  from history: must not reintroduce the #1743-r3 exact-fit livelock
  (re-honor must not re-CHARGE pass1) nor the #1732 lowest-rate
  monopoly (remainder only, once).

Acceptance gates for the fix PR (decisive cells re-run, before/after
in PR body): small4+24g 3g/6g ≥ 85% of shape (from ~70%); small4+9g
all classes ≥ 85%; small4-alone and solo baselines unregressed; 24g
not above its ceiling-division residual; `cos-gate1` +
`cos-simul-load-smoke` green; default `proportional`-mode unit suites
byte-identical where applicable.

### Path B — config-only mitigation (operator-actionable today)

`buffer-size` on the mid schedulers lifts the lease ceiling
(buffer 4m → ceiling 512 K → watermark = R_i × 200 µs): predicted to
recover most of 6g's gap with zero code change. §6 cell P runs
exactly this as the decisive H1' perturbation; if confirmed it ships
as a fixture/ops note regardless of Path A.

### Path C — H1-refuted fallback (new instrument)

Not reached: H1' is confirmed by §2.3 + §4. Recorded for form: had
the counters contradicted the model, the next instrument would have
been per-queue honored-vs-delivered byte counters (the §4 model makes
them derivable from existing counters, so no new instrument is
needed even for the fix's validation).

### PLAN-KILL invitation

Reviewers should kill this plan if: (a) the §3 arithmetic is wrong
(show a division of 22.6 G that yields 3g/6g ≈ 70% AND 24g ≈ 49%);
(b) the §2.2 +9g cell admits a physical explanation at 15.2 G
aggregate (name it concretely — e.g. a per-flow-count TCP artifact —
and a cell that would show it); or (c) the §4 watermark derivation
misreads the code (quote the lines).

## 6. Remaining measurement program (this round, pre-review)

Executed after the in-flight #1868 smoke session frees the cluster
lock; master-content build redeployed first (in-band version check),
fixture re-applied:

- **Cell P (decisive H1' perturbation)**: `set class-of-service
  schedulers scheduler-6g buffer-size 4m` (+ same for 3g in a second
  variant), small4+24g, 2 reps. **Prediction (registered in advance):
  6g rises from ~70% to ≥ 85%** (watermark 32 K → 150 K; accrual at
  366 µs cadence = 45.75 K/visit/worker → 6.0 G nominal, minus
  share-stranding). 3g variant: smaller lift (share-bound), to ~80%.
  If P moves < 5 pts, H1' is materially wrong → Path C.
- **Cell U (headroom bound)**: unshaped variant (atomic `delete
  class-of-service` + filters), same 60-stream small4+24g port mix,
  2 reps → C_phys(mix) pin for the fix's acceptance gates.
- **Restore + sanity**: re-apply fixture, 1 rep small4+24g ≈ 70%.

## 7. Blast radius

None this round (docs + measurements only). Path A touches the
hottest code in the project (`queue_service`, `shared_cos_lease`,
`token_bucket`) — the /engineer round inherits the full hot-path
discipline + fairness differential-test precedent (#1763).

## 8. Risks

- **Shared-cluster contention**: a concurrent #1868 deploy+smoke
  session held the lock mid-session; no cells were contaminated (all
  cells completed before its deploy began; in-band tree-equality
  check pins the build) but the remaining §6 cells must re-verify
  version in-band. One of this session's commands (the first unshape
  attempt) silently no-oped on lock timeout — §6 re-runs it under a
  verified lock hold with output checks.
- **B/honor is a ratio of all-worker sums** — per-worker skew is
  averaged; the model's per-worker uniform-cadence assumption is an
  approximation. The §2.3 fits land within 2-5% anyway.
- **24g 2×-watermark attribution (stale-token)** is inferred from
  arithmetic (66,379 ≈ 2 × 32,768), not from a dedicated counter
  (Q1).
- **Single fraction (0.7) and single fixture** — same caveat as the
  1614 corpus.

## 9. Open questions for reviewers

- **Q1**: Hostile-check §4.5 (stale-token double-spend at completion
  lag). Alternative explanations for B/honor ≈ 66 K on a queue whose
  top-up watermark is 32,768 B are welcome — but must fit p2adm ==
  budget_breaks and the per-visit token plumbing.
- **Q2**: Path A1 — is there a reason the `burst/8` lease ceiling
  must apply to QUEUE leases (not just root), e.g. credit-pool
  protection (`max_total_leased` interaction)?
- **Q3**: Is A2 (re-eligibility) needed if A1 alone closes the gap at
  the observed 366 µs cadence? (A1-only prediction: 6g → ~6.0 G
  nominal; 3g stays share-bound ~90%.)

## 10. Test/repro plan

`run-cell.sh` (archived) + cells `base-r{1,2}`, `agg9-r{1,2}`,
`agg12-r{1,2}` (raw/ committed), plus §6 cells P/U/sanity on
completion. Delta analysis script: `honor-analysis.py` (archived).

## 11. Reviewer questions (round 1)

1. Ratify the §3 kill-exit refutation (arithmetic + the +9g cell), or
   show the division that explains the data.
2. Ratify the §4 worked trace (esp. the `burst/8` → 12 K → 32 K-bank
   watermark chain) against the quoted lines.
3. Adjudicate Q1-Q3.
4. Path A scope: A1+A2 vs A1-first-then-measure.
5. Is cell P's registered prediction the right falsification bar
   (≥ 85% vs < 5 pt movement)?
