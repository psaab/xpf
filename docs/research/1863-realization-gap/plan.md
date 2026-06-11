# #1863 — CoS guarantee-rate honored-realization gap: ceiling kill-exit closed; rate-setter localized to the v8 lease claim path

- **Revision:** v2 (round 1 — v1's watermark/lockout sub-hypothesis was
  falsified BY THIS SESSION'S OWN registered-prediction cell P and the
  mechanism section rewritten before first review; v1 is in git history)
- **Date:** 2026-06-11
- **Branch:** `research/1863-realization-gap`
- **Mode:** /research — no production code; measurement + code-trace evidence
- **Measured target:** loss userspace cluster; build content-identical to
  master `6d8fa810d` (first cell batch: deployed `…2195-gaff208a18`,
  `git rev-parse 6d8fa810d^{tree} == aff208a18^{tree}`; second batch:
  this branch deployed, in-band `…2197-g7b076ee2e` on BOTH nodes);
  fixture `test/incus/cos-iperf-config.set` (shaping 25g,
  `guarantee-rate 0.7`, equal-flow OFF, verified in-band per batch)

## 1. Problem statement

#1863 inherits one question from the #1614 close (Reading-B residual):
Phase-1-honored mid classes (3g/6g) realize ~70-71% of shape under a
Phase-2 aggressor (24g) vs 88-91% alone — a ~16-19 pt
honored-realization gap, monotone in `R_i`, with a ratified PLAN-KILL
exit if the gap is physical-ceiling division. This round: (1) the
kill-exit, (2) quantitative confrontation of hypothesis H1 with
per-queue counters and perturbation cells, (3) fix paths.

## 2. Measurement evidence (section of record)

All cells: loss cluster, push, `loss:cluster-userspace-host` →
172.16.80.200, 30 s TCP, 12 streams/class unless stated, serialized
under `/tmp/xpf-cluster.lock`, runner `run-cell.sh` (archived; same
harness as the 1614 corpus). Raw iperf3 JSON + before/after `/metrics`
under `raw/`; snapshots from the RG0-primary node, CoS runtime
location verified per-cell via nonzero deltas. Analysis scripts
`honor-analysis.py` archived alongside.

### 2.1 Baseline re-anchor on master content (small4+24g)

| Class | r1 | r2 | r3 (post-redeploy) | 1614 corpus mean (9 reps) |
|-------|----|----|--------------------|----------------------------|
| 100m | 93.5 | 93.9 | 93.9 | 94.2 |
| 1g | 87.4 | 87.0 | 90.1 | 88.4 |
| **3g** | 68.9 | 73.1 | 72.5 | 71.1 |
| **6g** | 66.4 | 70.8 | 71.7 | 70.0 |
| 24g | 43.3 | 50.4 | 50.6 | 49.1 |
| SUM | 17.4G | 19.5G | 19.6G | 18.7-19.5G |

(p6g-r3 and sanity-r1, run during foreign failover ops — §8 — also
land in this band: 3g 71.4/73.0, 6g 72.1/75.1.) The phenomenon
reproduces unchanged on current master.

### 2.2 Aggressor-rate sweep (aggressor = port choice; config-free)

| Cell | Σ demand | delivered r1/r2 | 3g | 6g | aggressor |
|------|----------|-----------------|----|----|-----------|
| small4 alone (1614 §2.3) | 10.1G | 9.0/9.2G | 87.5-91.5 | 88.7-91.1 | — |
| +9g | **19.1G** | **15.2/15.1G** | 81.4/80.1 | 81.3/81.9 | 76.9/76.5 |
| +12g | 22.1G | 15.4/16.8G | 77.9/79.5 | 74.6/78.9 | 63.6/73.0 |
| +24g | 34.1G | 17.4-19.6G | 69-73 | 66-72 | 43-51 |

### 2.3 Unshaped-mix ceiling (cell U): C_phys(mix) = 23.2 G

Same 60-stream 5-port mix, CoS + classifier filters deleted in ONE
atomic commit (verified `configuration path not found`), 2 reps:
aggregate **23.27 / 23.22 G** (≈ even 4.3-5.0 G per port — TCP-fair,
shape-independent as expected with shaping removed). Fixture restored
atomically afterwards; sanity cell reproduced the baseline.

### 2.4 Cell P — registered-prediction watermark perturbation (FALSIFIED v1's H1')

`set class-of-service schedulers scheduler-6g buffer-size 4m` raises
the 6g queue-lease `lease_bytes` 12 K → 150 K and the per-visit top-up
watermark 32,768 → 150 K (§4 chain). v1's registered prediction: 6g
≥ 85% of shape. Result:

| | base-r3 (no buffer) | p6g-r1 (buffer 4m) |
|---|---|---|
| 6g %shape | 71.7 | **68.5** |
| 6g B/honor | 31,505 | **57,706** |
| 6g phase1 admissions | 537,005 | **280,570** (interval 366→641 µs) |
| 6g sent GB | 16.92 | 16.19 |

The watermark change DID take effect in the dataplane (B/honor +83%,
honors −48%) — but the realized rate is INVARIANT. The per-visit
spend pattern re-batched; the byte rate did not move. (p6g-r2
corroborates at B/honor 36.6 K with a mid-cell foreign daemon restart
— §8; r1 is the clean rep.)

**Adjudication: the waterfill-layer per-visit token clamp and the
once-per-epoch honored lockout are NOT the rate-determining
mechanism.** They set batching granularity only.

### 2.5 Grant-side accounting: the v8 lease grant flow IS the realized rate

Per-cell `Δ xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total`
(all workers) vs `Δ drain_guarantee_sent_bytes_total` (all queues):

| Cell | v8 grants | guarantee sends |
|------|-----------|-----------------|
| base-r3 | 76.9 GB | 77.2 GB |
| p6g-r1 | 79.2 GB | 74.9 GB |
| agg9-r2 | 59.5 GB | 59.5 GB |

Grants ≈ sends in every shaped cell: per-class realized throughput =
per-class lease grant throughput. The question "why 70%?" is a
question about `acquire_v8`, not about the selector.

### 2.6 Stream-count perturbation (s24): more flows do not help

24 streams/class (same mix): 3g 63.8-67.0%, 6g 63.3-66.0% — slightly
WORSE than 12 streams, with heavy retransmits (3-28 K). A
flow-count-uniformity account of the stranding (more flows → smoother
per-worker demand → less stranding) is not supported. (s24-r1/r2 ran
with the 6g buffer-size still applied due to a failed revert — §2.4
shows that knob is rate-neutral, and s24-r3 reproduces clean.)

### 2.7 Inelastic-demand discriminator (udp3g): supply-side confirmed

The strongest alternative to a lease-side account is demand-side: TCP
cwnd/RTT collapse under aggressor-inflated queueing could depress
demand so grants merely FOLLOW it (grants==sends would hold either
way). Discriminator: 3g as open-loop UDP at 110% of shape (~3.3 G
offered; generator ceiling ~2.9 G/process is still well above the
~2.1 G supply-side prediction) against a FULL-strength 24 G TCP
aggressor — 2 reps:

| | 3g delivered | 3g loss | 6g (TCP) | prediction if demand-side | if supply-side |
|---|---|---|---|---|---|
| udp3g-r1 | 2.07 G (68.9%) | **37.4%** | 69.0% | ~2.9 G, ~0-3% loss | ~2.1 G, ~25-30% loss |
| udp3g-r2 | 2.04 G (68.0%) | **38.1%** | 66.9% | | |

Inelastic constant-pressure demand is dropped down to the SAME ~69%
level as elastic TCP. The constraint is the supply path, not TCP
dynamics. (The 1614 corpus's UDP cell showed 3g at 85-88% — but its
24g sender was generator-capped at ~2.9 G, i.e. a weak aggressor;
these two cells bracket the variable: weak aggressor 85-88%, full
aggressor 68-69%, inelastic demand in both.)

### 2.8 Per-queue counter signatures (carried from §2.1-2.4 cells)

- Waterfill epoch turnover: alone ~48 µs/worker-epoch (Phase-2 wrap
  turnover) vs 135-155 µs (+24g, time-tick-dominated): the lockout is
  binding only under a backlogged Phase 2 — but per §2.4 this changes
  batching, not rate.
- #1847 undergrant causes (every aggressor cell): `share_exhausted`
  1.7-4.4 M/run ≫ `class_cap` 7-22 K ≫ others — workers exhaust their
  OWN per-epoch share while class-cap room remains.
- Per-worker v8 grant totals skew up to ~2× (and one worker at 0.0 GB
  in p6g-r1): RSS placement + per-worker cadence variance is large.

## 3. KILL-exit: unshaped-mix-ceiling — CLOSED, NOT TAKEN

Three independent refutations:

1. **Arithmetic**: dividing C_phys = 22.6 G (solo-uncapped pin, 1614
   §2.1) over demand {0.1, 1, 3, 6, 24}: any work-conserving division
   (per-class water-fill or per-stream fair) saturates all four
   small/mid classes at FULL shape (×~94% solo health) and gives 24g
   the residual ~12.5 G (52%). Observed 24g ≈ 49-51% matches the
   residual; observed mids 70-71% vs predicted ~94% do not. No
   division of 22.6 G yields the data.
2. **+9g cell**: demand 19.1 G, delivered 15.1-15.2 G — ~4 G of
   demanded, in-shape traffic undelivered with NO ceiling within
   reach; aggregates across the sweep (15.1 → 16.8 → 19.6 G) are
   ordered OPPOSITE to what a fixed ceiling division produces.
3. **Direct measurement**: C_phys(mix) = 23.2 G (§2.3) — the shaped
   system leaves 3.6-8.1 G of measured headroom on the table.

## 4. Mechanism (code-grounded, post-falsification)

### 4.1 What was verified and then adjudicated NOT rate-determining

The issue's H1 chain at the waterfill layer is real code: stable
quantum charge (`phase1_cost`, `cos/queue_service/mod.rs:1048`),
token-clamped send (`:1049-1053`), honored-bit lockout for the rest
of the epoch (`:1078-1079`, both phases `:938`, `:1126-1133`); and
the per-visit top-up watermark is rate-INDEPENDENT (~32,768 B) for
every default-buffer class — `lease_ceiling = burst/8` with queue
burst = `buffer_bytes.max(96 K)` clamps `lease_bytes` to 12 K
(`types/shared_cos_lease/mod.rs:888-894`, `coordinator/mod.rs:1573`),
then the §1630 bank floor lifts the watermark to 8 frames
(`cos/token_bucket.rs:248-252`). All confirmed against source and
against counters (B/honor ≈ 17-34 K ≪ quanta 75/150 K).

But cell P (§2.4) shows the realized rate is INVARIANT to a 4.7×
watermark change, and §2.5 shows realized == lease grants. So these
selector-layer mechanics shape batching; the BYTES are set one layer
down.

### 4.2 The rate-setter: v8 lease claim efficiency

`acquire_v8_with_cause` (`types/shared_cos_lease/mod.rs:1304`)
implements, per class (per-queue lease shared by 6 workers):

- per-lease-epoch class cap = `rate × elapsed` (+ bounded lag carry)
  published at rotation (`rotate_epoch_v8.rs:216-218`);
- per-worker share = `cap × my_flow_buckets / total_flows`
  (`rotate_epoch_v8.rs:350-356`) — flow-count proportional;
- grants bounded by OWN share (ShareExhausted break, `:1386-1388`);
  **strict no-surplus**: a worker may NOT claim peers' unclaimed
  share (the deliberate post-#1231-v5.5 design, comment at
  `:1486-1496`); the narrow `bypass_grace` escape arms only when
  three conditions co-fire (`rotate_epoch_v8.rs:313`), which the
  §2.8 counters show effectively never happens in these cells;
- shares are NOT carried for a worker that fails to claim them: a
  worker only acquires when the drain loop visits its queue
  (`maybe_top_up_cos_queue_lease` at the selector sites), so a
  worker that visits less than ~once per 200 µs lease epoch lets
  its share evaporate at rotation (rotation lag carry compensates
  ONLY the global rotation gap, not per-worker claim gaps).

Realized_i = claimed grants = `cap_i × claim_efficiency_i`, with the
measured claim efficiency ~70-72% (mids, +24g), ~80-82% (+9g/12g),
~88-91% (alone).

**Why the aggressor lowers claim efficiency (cross-class coupling):**
classes do not share lease budgets — the coupling is CPU/visit
cadence. A backlogged Phase-2 aggressor consumes most selector calls
and per-pass drain time (24g takes one ~66 KB batch per call —
phase2 == budget_breaks), stretching each worker's revisit interval
to the mid-class queues (6g eligible-visit spacing roughly doubles
vs alone in §2.8 data); slower per-worker acquire sampling against a
fixed 200 µs share-evaporation clock + strict no-reclaim = stranded
share — and §2.7 proves the depressed delivery is supply-side (an
inelastic 110%-offered 3g is dropped to the same ~69%), closing the
demand-side (TCP cwnd/RTT) alternative. The s24 cell (§2.6) is
consistent (more per-pass work →
slightly worse); cell P is consistent (bigger banking per visit
cannot recover share that was never claimable); the undergrant-cause
mix is the direct signature (own-share exhaustion dominant on
fast-sampling workers, class-cap room left by slow-sampling ones).

What this session did NOT pin: the exact split between (a)
share/demand mismatch across workers (flow-count-proportional shares
vs unequal per-worker deliverable demand) and (b) pure
sampling-loss (visits < 1 per epoch). Both are inside `acquire_v8`'s
strict-share design; both are addressed by the same family of fixes
(§5); the split is measurable during /engineer with one added
per-class counter pair if needed (grant-requested vs grant-given
already exists per-worker; the per-class split is derivable from the
§2.5 accounting at fix-validation time).

### 4.3 Residual open observation (Q1)

24g B/honor ≈ 66-79 K exceeds the 32,768 + ε bound a single top-up
implies. Most plausible: tokens are debited at TX COMPLETION
(`cos/tx_completion.rs`), so back-to-back Phase-2 admissions
(every selector call) read not-yet-debited token state — an
amplification structurally unavailable to lockout-spaced honored
classes. Secondary now that the watermark layer is adjudicated
non-rate-determining, but reviewers should sanity-check the reading.

## 5. Paths

### Path A — work-conserving guarantee-phase lease claim (RECOMMENDED)

Let unclaimed per-worker share be reclaimable within the epoch for
guarantee-phase exact classes, bounded by the class cap (which is
exact-rate-derived, so the hard cap and Gate-4 semantics are
preserved): either (A-i) a post-grace second-pass claim against
remaining class room (resurrecting the pre-v5.5 work-conserving path
but ONLY for the guarantee phase, keeping equal-flow caps when
enforcement is on), or (A-ii) per-worker unclaimed-share carry into
the next epoch with a small cap (1-2 epochs). Constraint inherited
from #1231/#1290: must not let low-flow workers starve multi-flow
workers' per-flow rates (the iperf-d 770 Mbps regression that
motivated strictness) — the difference here is the reclaim is
bounded by class-cap room that today simply evaporates (claiming it
cannot reduce any peer's grants, only reduce stranding; the v5.5
regression came from UNCONDITIONAL half-epoch slack-claiming, not
from room-bounded reclaim).

Predicted effect (from §2.5 accounting): claim efficiency → ~1 minus
sampling losses; mids from ~70% toward their alone level (88-91%);
24g residual rises toward its ceiling-division share; aggregate
toward min(Σ caps under ceiling, C_phys(mix) − CoS overhead).

### Path B — demand-weighted shares

Replace flow-count-proportional shares with demand-weighted (EWMA of
recent per-worker grants or of requested bytes). Attacks mismatch (a)
but not sampling loss (b); higher regression risk for the per-flow
fairness contract (shares follow throughput → rich-get-richer
feedback needs damping). Viable as a complement, not the lead.

### Path C — decouple claiming from drain visits

Per-worker lease pump (claim share into the token bank on a timer or
on RX/admission) so share claiming no longer depends on selector
cadence. Attacks (b) directly but adds work to the hottest path and
new cross-thread interaction with rotation; only if A under-delivers.

### PLAN-KILL invitation

Kill if: (a) §3 arithmetic is wrong (exhibit a division of 22.6 G
matching the data); (b) C_phys(mix) = 23.2 G is an artifact (name the
mechanism — note the cells bracket it: unshaped delivered 23.2 G on
the same wire/minute as shaped 19.6 G); (c) §4.2 misreads
`acquire_v8` (quote lines); (d) Path A is shown to necessarily
reintroduce the #1231/#1290 per-flow regression (worked trace
required).

## 6. Acceptance gates for the fix (/engineer phase)

Before/after on the decisive cells (12-stream, 2-3 reps each):
small4+24g mids ≥ 85% of shape (from ~70%); small4+9g all classes
≥ 85%; small4-alone + solo baselines unregressed (≥ current);
aggregate ≥ 21 G on small4+24g (vs 19.5; C_phys(mix) 23.2 minus
overhead margin); per-flow fairness contract intact
(`docs/fairness-regimes.md` Cstruct gate + `cos-gate1` +
`cos-simul-load-smoke`); equal-flow ON cells byte-sane (#1745/#1746
suites); full `cargo test --release` + `go test ./...`.

## 7. Blast radius

This round: docs + measurements only. Path A touches
`shared_cos_lease` (rotation + acquire) — the hottest shared
structure in the dataplane; /engineer inherits hot-path rules,
seqlock/atomics discipline (#1643 ordering contract), and the #1763
differential-test precedent for fairness-neutral claims.

## 8. Risks + session incidents (lock discipline)

- **Three foreign-interference events this session** on the shared
  cluster: (i) a #1868 smoke session self-deadlocked holding
  `/tmp/xpf-cluster.lock` (its inner `wg-interop.sh` per-command
  flock waits on its own outer hold — 50 min stalled, cluster idle);
  this session killed that tree to free the lock after verifying its
  deploy+CoS apply had completed, and left
  `/tmp/1868-deadlock-note.txt` for the owner. (ii) an external
  SIGTERM restart of fw0's xpfd at 03:36:30 PDT mid-cell p6g-r2
  (cell excluded from primary evidence; r1 is the clean rep).
  (iii) manual RG0 failovers at ~03:44 PDT around the p6g-r3
  config-edit (the set never landed → p6g-r3 is a clean extra
  BASELINE rep, labeled as such). All decisive claims rest on cells
  with in-band version checks and counter-consistency validation.
  Harness rule worth codifying: self-serializing scripts must not be
  invoked under an outer hold of the same lock; cluster mutations
  require the lock.
- **Cell P interpretation**: the 6g `buffer-size 4m` knob was proven
  to reach the dataplane via its counter signature (B/honor +83%) —
  the rate-invariance is not a no-op artifact.
- **Pooled grant metrics**: §2.5 grant totals are all-class pooled
  per worker (#1692 caveat) — the per-class identity is established
  by the class-level send counters and the cells where a single knob
  isolates one class.
- Single fraction (0.7), single fixture, push direction only — same
  scope caveats as the 1614 corpus.

## 9. Open questions for reviewers

- **Q1** (§4.3): stale-token completion-lag reading of the 24g
  per-admission bytes.
- **Q2**: Path A's room-bounded reclaim vs the #1231 v5.5 strictness
  rationale — is the "reclaim only evaporating room" argument sound,
  or does the iperf-d regression generalize to it?
- **Q3**: is the (a)/(b) split (share mismatch vs sampling loss)
  worth a dedicated pre-fix instrument, or is fix-validation-time
  derivation (§4.2 end) sufficient?
- **Q4**: should the `burst/8` queue-lease ceiling fix (v1's A1)
  ship anyway as hygiene (it silently discards configured rate for
  default-buffer classes) even though cell P shows it is not the
  rate-setter here?

## 10. Test/repro plan

Executed: `base-r{1,2,3}`, `agg9-r{1,2}`, `agg12-r{1,2}`,
`p6g-r{1,2,3}`, `s24-r{1,2,3}`, `unshaped-r{1,2}`, `sanity-r1` — all
under raw/ with metrics snapshots; scripts `run-cell.sh` +
`honor-analysis.py` archived. Re-runnable on any master deploy +
`apply-cos-config.sh`.

## 11. Reviewer questions (round 1)

1. Ratify the §3 kill-exit closure (three-way: arithmetic, +9g,
   C_phys(mix) measurement).
2. Ratify §4's two-step adjudication: waterfill layer verified real
   but falsified as rate-setter (cell P invariance + grants==sends);
   lease claim path confirmed as rate-setter.
3. Adjudicate Q1-Q4.
4. Path choice: A-i vs A-ii lead, B/C as complements.
5. Are the §6 gates the right falsification bar for the fix?
