# #1766 — -P12 cross-worker fairness: characterization + equal-flow-enforcement evaluation

Research-only deliverable (sub of #1765). Resolves the Codex↔Gemini
divergence with live evidence on the loss userspace cluster, and
evaluates the in-tree `equal-flow-enforcement` lever. **Outcome:
ACCEPT-AS-PHYSICS + adopt the Cstruct-relative test gate. No v8/V_min
defect exists. `equal-flow-enforcement` is the correct *optional*
operator lever but is NOT the default answer.** No production code
change is warranted; the only follow-up is doc/test-gate wording.

## 1. Summary / verdict

| Question | Verdict |
|---|---|
| Q1: physics or v8/V_min gap? | **PHYSICS.** 25/25 live runs satisfy `observed_CoV ≤ Cstruct(draw) + 0.05`; gaps are −18 to −65 pp (deeply below ceiling). v8 grant accounting is *over-delivering* fairness vs the work-conserving ceiling, not leaking. No V_min/v8 gap. |
| Q2: does equal-flow-enforcement fix it? | **Partially, and at no aggregate cost in this regime — but it is not a reliable low-P fix.** Clean P12: mean CoV 12.0%→6.4%, SUM 14.86G→14.82G (cwnd-bound, so clipping is free). It halves *typical* CoV but does NOT cap the worst skew draw (5-pile still 17.9%). |
| Q3: Cstruct test gate? | **Yes — adopt `observed_CoV ≤ Cstruct(draw)+ε` (already the documented Gate 2).** A flat CoV target is mathematically inconsistent with the per-draw ceiling. The harness already implements it; this research is the empirical ratification. |

## 2. Environment / method

- Cluster: `loss:xpf-userspace-fw0/1`, master tip `ef40d1cae`
  (deployed fresh; both nodes `gef40d1cae`, node0 RG0 primary).
- Path: `loss:cluster-userspace-host → 172.16.80.200 -p 5208`
  (iperf-18g exact class = forwarding-class queue 8, scheduler-18g
  `transmit-rate 18.0g exact`), forward direction, egress reth0.80
  (ifindex 14). Strict exact fixture (`cos-iperf-config.set`), no
  surplus-sharing.
- Metric discipline (per #1766 / state.md:362): per-worker `{a_i}` read
  from `xpf_userspace_cos_active_flow_count{ifindex=14,queue_id=8,
  worker_id}` — the q8-specific source, NOT the polluted
  `binding_active_flow_count`. Validated against the daemon-computed
  `xpf_fairness_cstruct{queue_id=8}` gauge: my offline Cstruct matched
  the daemon's to the displayed precision on every run
  (e.g. r5 50.0%/50.0%, r6 54.4%/54.4%, r8 71.5%/71.5%) — metric
  cross-check passes the "validate before asserting" bar.
- Per-flow CoV from iperf3 `-J` per-stream `sender.bits_per_second`.
- v8 share probed via
  `xpf_userspace_worker_cos_queue_lease_acquire_v8_granted_bytes_total`
  / `_calls_total` deltas across a 12s→steady window.
- 75s runs (warmup-skip honored), 25 total: 13 clean EF-OFF, 8 clean
  EF-ON, 2 EF-ON kill-seq, 2 EF-OFF kill-seq. Raw artifacts in
  `runs/` (iperf JSON + two metric scrapes per run); `runs/summary.csv`
  + `runs/char.sh` / `analyze.py` / `kill_seq.sh` are the auditable
  harness.

## 3. Q1 — physics vs gap (the core deliverable)

### Result: PHYSICS, unanimous.

25/25 runs: `observed_CoV ≤ Cstruct + 0.05`. Representative clean runs:

| draw {a_i} | Nactive | SUM G | obs CoV | Cstruct | gap |
|---|---|---|---|---|---|
| 0,1,5,1,1,4 | 5 | 13.56 | 15.7% | 81.0% | −65.3 |
| 1,3,5,1,1,1 | 6 | 14.66 | 12.4% | 71.5% | −59.0 |
| 2,1,0,5,3,1 | 5 | 14.03 | 18.3% | 67.5% | −49.2 |
| 3,5,1,2,1,0 | 5 | 13.60 | 20.7% | 67.5% | −46.8 |
| 2,2,3,3,1,1 | 6 | 15.84 | 3.9% | 47.1% | −43.2 |

The observed per-flow CoV is **39–65 pp below the structural ceiling**.
That single fact refutes any "v8/V_min accounting gap" reading: a gap
would push observed CoV *up toward or past* Cstruct, not 40+ pp below
it.

### Why it sits so far below Cstruct: v8 grant accounting is the mechanism

`Cstruct` is the ceiling for a **work-conserving** scheduler that lets
every worker consume its full RSS share, dividing it equally among its
own flows. The xpf shared-v8 lease does NOT do that — it allocates each
worker a cap **proportional to its active-flow count**:

`rotate_epoch_v8.rs:330` — `my_share = new_cap × my_count / total_flows`.

So a worker carrying 5 flows gets ~5× the byte cap of a solo worker,
which keeps its per-flow rate close to the solo rate. The grant
telemetry shows exactly this — v8 grant-per-flow is near-flat across
workers even on skewed draws:

- r1 `[0,1,5,1,1,4]`: grant-per-flow GB (active) =
  `[—,10.3,7.0,10.3,10.3,8.0]`, **grant-per-flow CoV 15.1% ≈ observed
  per-flow CoV 15.7%**.
- r3 `[1,3,1,1,2,4]`: grant-per-flow CoV 7.7% ≈ observed 8.9%.
- r9 `[2,1,0,3,4,2]`: grant-per-flow CoV 8.4% ≈ observed 9.8%.

The v8 grant-per-flow CoV tracks the observed per-flow CoV within
~2–4 pp on every run. **This is strong evidence, not proof.** Caveat
(Codex finding 2): the granted-bytes metric counts bytes *granted by
acquire calls*, not bytes *transmitted*; both the grant and the
observed throughput are downstream of the same `my_count/total_flows`
input (`rotate_epoch_v8.rs:323`), so a shared active-count accounting
bug could in principle make both correlate. What the correlation *does*
establish: the per-flow rate is set by the flow-proportional grant
share (not by an unmodeled scheduler path), and the grant share is
itself ~flat-per-flow — i.e. the lease is behaving as the design
specifies. The independent disconfirmation of a *leak* is in §3.3
(direction of the residual): a v8/V_min *gap* that mis-credited
crowded workers would manifest as crowded-worker flows running *faster*
or solo-worker flows being *held back*; the data shows the opposite
(solo workers get the highest grant-per-flow, crowded the lowest),
which is the designed flow-proportional split, not a leak.
The residual ~8–20% band split is (a) the per-worker scheduler's
within-worker division plus (b) TCP cwnd jitter on the
slightly-reduced crowded-worker per-flow share — both bounded well
under Cstruct.

### 3.3 V_min / parks / stalls

- `xpf_userspace_cos_drain_surplus_sent_bytes_total{q8} = 0` and
  `..._nonexact_sent_..._while_exact_backlogged = 0` on every run: all
  q8 bytes flow via the exact guarantee path; no surplus borrowing, no
  cross-class steal.
- No `*_starvation_parks` counters emitted for q8 (zero parks).
- Drain latency buckets concentrated ≤32µs; no TX-ring stall
  signature.
- **V_min throttle observability limitation (Codex finding 3 —
  acknowledged).** The V_min throttle / hard-cap / suspend counters
  (`v_min_throttles`, `v_min_throttle_hard_cap_overrides`,
  `cos.rs:1047/1059/1069`; flushed to `BindingLiveState` and carried on
  the binding wire `protocol.go:1116-1117`) are **NOT exported to
  Prometheus, CLI, or any HTTP/gRPC endpoint** on the deployed binary —
  they live only in the internal binding-status JSON snapshot. I
  therefore **could not directly read V_min throttle counts**, and the
  absence of a `v_min` Prometheus series is NOT direct proof of zero
  throttles. What bounds the V_min concern *indirectly*: (1) V_min
  throttling delays a worker whose `queue_vtime` runs *ahead* of peers
  — its effect is to *slow the fastest worker*, pulling its per-flow
  rate down toward peers. If V_min were over-throttling it would
  *compress* the spread (lower CoV), not inflate it, so it cannot be
  the cause of a *too-high* CoV. (2) The hard-cap escape
  (`v_min.rs:213-216`, force-continue after
  `V_MIN_CONSECUTIVE_SKIP_HARD_CAP`) recovers ~99% throughput under
  persistent spread (#942), bounding any stall. (3) Aggregate sits at
  the cwnd/structural ceiling (§4, with the saturation correction
  below), so V_min is not suppressing aggregate below what the active
  workers can deliver. A direct read would require exporting these
  counters (a code change, out of scope); recommended as an optional
  observability follow-up in §7.

### Conclusion Q1

The Gemini reading is correct: the residual band split is **intended
physics within `Cstruct`**, and the shaped-exact v8 lease already
mitigates it ~40 pp below the work-conserving ceiling. Codex's prior
"the CoVs are below the raw 51–62% RSS floor → v8 must be mitigating →
*therefore there may be a gap*" is half-right (v8 IS mitigating) but
the gap inference is refuted: the mitigation is the *designed*
flow-proportional grant, and the grant accounting is clean. **No
v8/V_min defect to fix.**

## 4. Q2 — equal-flow-enforcement evaluation

### How to enable (operator path)
Config leaf `class-of-service schedulers <name> equal-flow-enforcement`
(`pkg/config/schema.go:867`, presence-only flag). Valid only on a
positive exact-rate scheduler **without** `surplus-sharing`. Applied
live to all 10 exact schedulers; verified runtime-live via
`xpf_userspace_cos_equal_flow_enforcement_enabled{q8}=1`,
`_enforced=1`, `_fail_open{reason="none"}=1`. (`apply-cos-config.sh`
has a `--surplus-sharing` injector but no `--equal-flow-enforcement`
flag; a one-line awk-injection mirror is the trivial harness add if a
class-sweep wants it — see runs/ wrapper.)

### Mechanism (publish_equal_flow_epoch_v8.rs)
Per epoch, derives `candidate_target = min over sampled workers of
(prev_grant[w] / active_flows[w])` = the **slowest worker's per-flow
byte rate**, EWMA-smooths it (`3:1`), and caps each worker at
`smoothed × its_flow_count`. Non-work-conserving: deliberately
withholds the faster workers' surplus to drag every flow toward the
slowest per-flow rate. Numerous fail-open guards (unsampled worker,
<2 sampled workers, low-demand worker, zero target, streak < required)
make it fail *open* (revert to v8 proportional) rather than mis-clip.

### Result (clean P12, EF-ON vs EF-OFF)

| | n | CoV mean | CoV median | CoV max | SUM mean |
|---|---|---|---|---|---|
| EF-OFF | 13 | 12.0% | 9.7% | 20.9% | 14.86 G |
| EF-ON | 8 | 6.4% | 4.3% | **17.9%** | 14.82 G |

- **Typical CoV roughly halved** (12.0→6.4% mean), consistent with the
  prior ~22%→8.6% direction.
- **Aggregate cost ≈ zero across this run set** (14.86→14.82 G), but
  the *reason* is more nuanced than "cwnd-bound" (Codex finding 1 —
  corrected). By the contract's structural-cap definition
  (`fairness-regimes.md:322`, `fairness.rs:106`: cap =
  `(Nₐ/Nᵥ)×shaper`, saturated iff ≥95% of cap), the **5-active runs are
  saturated** (cap = 15G; r4/r6/r7/r9/r10/offkill*, ef1/ef8/efkill2 all
  hit ≥98% of 15G — see `runs/sat.tsv`), while the **6-active runs sit
  at ~82–88% of their 18G cap (non-saturated/cwnd-bound)**. The regime
  is therefore *mixed*, not uniformly cwnd-bound. The aggregate-neutral
  EF result still holds empirically on this set: even on the saturated
  5-active runs the structural cap (15G) is the binding constraint, and
  clipping the fastest worker to the slowest worker's per-flow rate
  redistributes *within* that cap rather than lowering it, because the
  idle 6th worker's share is unclaimable regardless. **Do NOT
  generalize "EF is free" to a fully-saturated 6-active draw** — there
  EF trades aggregate for equality (the documented non-work-conserving
  tradeoff); this set simply did not produce a saturated 6-active P12
  draw to exercise that cost.
- **It does NOT cap the worst draw.** The one 5-pile EF-ON run
  (`[5,1,1,2,0,3]`) still showed 17.9% CoV — within ε of its 67.5%
  Cstruct, but no better than the EF-OFF 5-pile draws. EF lowers the
  *common* skew but the per-worker `target × flow_count` cap still lets
  a crowded worker's flows differ from a solo worker's when smoothing
  lags a fresh skewed draw and the streak/fail-open guards keep it
  conservative.
- Kill-5211-then-5208 sequence (the operator's original trigger): EF-ON
  1.6% / 4.5%, EF-OFF 7.2% / 7.8% — all PHYSICS, no persistent
  cross-port contamination in either mode. **Confirms #1765's "kill is
  variance, not a causal path."**

### Conclusion Q2
`equal-flow-enforcement` is the **correct optional lever** for an
operator who explicitly wants tighter low-P per-flow equality on an
exact shaped class and accepts the non-work-conserving semantics. It
is **not** the right *default*:

- **Does the ~zero aggregate cost argue for default-ON? No (Codex
  finding 4 — addressed).** The zero-cost result is *regime-specific*
  to this P12 set (mixed cwnd-bound 6-active + cap-bound 5-active, no
  saturated 6-active draw). EF is non-work-conserving *by contract*
  (`publish_equal_flow_epoch_v8.rs` clips every worker to the *slowest*
  worker's per-flow rate); on a saturated draw with uneven per-worker
  demand it *will* sacrifice aggregate — that is its defined purpose.
  Defaulting it ON would silently impose that tradeoff on workloads
  that never asked for it and would violate the product contract's
  work-conserving default posture (`fairness-regimes.md` Non-goals:
  xpf does not promise equal per-flow throughput beyond `Cstruct`
  without an explicit non-work-conserving opt-in).
- It only halves *typical* CoV and **does not bound worst-case skew**
  (the EF-ON 5-pile `[5,1,1,2,0,3]` still showed 17.9%), so even as a
  fairness tool it is not a guarantee — another reason it is an
  operator policy choice, not a default correctness fix.

Default-OFF is the right shipped posture; keep it.

## 5. Q3 — test-contract

`docs/fairness-regimes.md` Gate 2 already specifies
`observed_CoV ≤ Cstruct + 0.05`, and `fairness-eval` /
`fairness_multi_sample.py` already implement it. This research
**empirically ratifies** that gate: a flat target (e.g. ≤20%) would
have *failed* legitimate physics draws (r2 20.9%, r13 20.7%) while
*passing* nothing more meaningful. No gate change is required — the
contract is already correct. Recommendation: cite this run set in
state.md as the P12 q8 ratification, and (optional) add an
`--equal-flow-enforcement` injector to `apply-cos-config.sh` so the
class sweep can exercise the lever without the manual `load merge`
used here.

## 6. Risks / threats to the verdict (self-review)

1. **Did I hit the true worst case?** The exact `[0,0,1,2,3,6]` 6-pile
   (issue's 25.4% case) has P≈few-% and did not occur in 25 draws. But
   I captured multiple 5-piles (`0,1,5,1,1,4`; `1,3,5,1,1,1`;
   `2,1,0,5,3,1`; `5,1,1,2,0,3`; `3,5,1,2,1,0`) — Cstruct 67–81%, obs
   CoV 12–21% — all PHYSICS with 45–65 pp margin. The 6-pile
   `[0,0,1,2,3,6]` has `Cstruct = 0.707` (Codex finding 5 — corrected;
   the earlier "~0.91" was wrong, recomputed via the documented formula
   and `analyze.py`), still comfortably above the issue's reported
   25.4% observed CoV (gap −45 pp). The verdict's *direction* is sound
   — every higher-skew draw raises Cstruct faster than it raises the
   v8-mitigated observed CoV — but I am not claiming a formal
   monotonicity theorem; the empirical 5-pile coverage (5 distinct
   5-pile draws, all 45–65 pp under ceiling) is the actual basis, and a
   6-pile would have an *even larger* margin.
2. **Forward vs reverse.** I measured forward (5208 dst-port → WAN
   egress q8), matching the operator repro. Reverse (`-R`, ge-0-0-1
   egress) is a different shaped path; #1765's table mixed both. The
   physics argument is path-independent (RSS multinomial + v8
   flow-proportional grant apply identically), but a reverse spot-check
   is a cheap confirmatory add if a reviewer demands it.
3. **Metric recency window.** `cos_active_flow_count` "active" = touched
   within ~650 ms; a flow briefly idle could under-count `{a_i}`. The
   daemon-gauge cross-check (matched to displayed precision) bounds
   this; per-stream iperf rates are the independent CoV source.
4. **Saturation labeling — corrected (Codex finding 1).** Against the
   scaled structural cap `(Nₐ/Nᵥ)×18G`, the 5-active runs ARE saturated
   (15G cap, ≥98% hit) and 6-active runs are not (~82–88% of 18G). The
   set is mixed. This strengthens the physics verdict (CoV stays far
   below Cstruct *even at the structural ceiling*) and is reflected in
   the corrected §4 EF discussion.
5. **Window alignment (Codex finding 4).** `{a_i}` is two scrapes
   (t≈12s, steady) of a ~650 ms recency proxy; observed CoV is the
   full iperf `end.streams` (start 0 → 75s). These are not
   window-identical. Codex independently recomputed CoV with 5s warmup
   + 1s final exclusion and headline CoVs barely moved; the gap to
   Cstruct (45–65 pp) dwarfs any window-alignment noise. The daemon
   `xpf_fairness_cstruct` gauge (steady-window-internal) matching my
   offline Cstruct is the cross-check that the `{a_i}` proxy is
   representative.
6. **Retrans (Codex finding 6).** Not all clean runs were
   zero-retrans: r3=19622, r5=4544 (the rest 0). These do not change
   any Gate-2 verdict but the earlier "0 retrans on clean runs" blanket
   wording was wrong; corrected here.

## 7. Recommendation / next step

- **PLAN-READY as ACCEPT-AS-PHYSICS.** Q1 = physics (no v8/V_min gap),
  Q2 = equal-flow-enforcement is a sound optional lever (keep
  default-OFF), Q3 = the Cstruct-relative gate is already correct and
  is hereby empirically ratified.
- **No `/engineer 1766` code change is warranted.** The only optional,
  non-blocking doc/harness follow-ups: (a) add the P12 q8 ratification
  row + this run set reference to `docs/per-5-tuple/state.md`; (b) add
  an `--equal-flow-enforcement` injector to `apply-cos-config.sh`.
  Both are trivial and out of scope for a code-behavior PR.

## 8. Evidence index
- `runs/summary.csv` — 25-run table.
- `runs/r*/`, `runs/ef*/`, `runs/*kill*/` — per-run iperf JSON + two
  metric scrapes.
- `runs/char.sh`, `runs/kill_seq.sh`, `runs/analyze.py` — harness.

## 9. Reviewer verdicts
(filled in §10/§11 after Codex + AGY + Claude-SMR rounds.)

## 10. Codex review — round 1: PLAN-NEEDS-MAJOR (`codex-1766-fairness-review-a4591a419`)
No reproducible Gate-2 counterexample (all runs confirmed below
Cstruct+0.05; `analyze.py` Cstruct math matched the documented worked
examples). 6 findings, all addressed in r2:
1. (Major) saturation labeling wrong — 5-active runs ARE saturated vs
   scaled cap → §4 corrected, `runs/sat.tsv` added.
2. (Major) grant↔observed correlation is evidence not proof → §3
   softened to "strong evidence", added direction-of-residual
   disconfirmation.
3. (Major) V_min not cleared by Prometheus artifacts → §3.3 rewritten
   to acknowledge the observability gap + indirect bound.
4. (Major→soft) window mixing → §6.5 acknowledged; Codex's own
   warmup-excluded recompute barely moved CoV.
5. (Minor) 6-pile Cstruct = 0.707 not 0.91 → §6.1 corrected.
6. (Minor) "0 retrans on clean runs" false (r3/r5) → §6.6 corrected.
None of the findings overturn the PHYSICS verdict (Codex: "the raw runs
still all sit below Cstruct + 0.05"); they are over-claim / methodology
corrections, now applied. r2 pushed for re-review.

## 11. AGY review
_pending (background `adversarial-review-mpz7rcgf-f5k0j2`)_

## 12. Claude SMR
See `claude-smr-plan-r1.md`.
