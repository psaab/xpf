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
~2–4 pp on every run. That is the smoking gun: **the v8 lease grant is
the dominant determinant of per-flow rate, and it is functioning as
designed** (flow-proportional, not leaking). The residual ~8–20% band
split is (a) the per-worker scheduler's within-worker division plus
(b) TCP cwnd jitter on the slightly-reduced crowded-worker per-flow
share — both bounded well under Cstruct.

### V_min / parks / stalls: clean

- `xpf_userspace_cos_drain_surplus_sent_bytes_total{q8} = 0` and
  `..._nonexact_sent_..._while_exact_backlogged = 0` on every run: all
  q8 bytes flow via the exact guarantee path; no surplus borrowing, no
  cross-class steal.
- No `*_starvation_parks` counters emitted for q8 (zero parks).
- No V_min throttle/hard-cap/suspend telemetry surfaced (V_min
  hard-cap counter is internal `consecutive_v_min_skips`, not a
  Prometheus series); the absence of parks + the flat grant-per-flow
  show V_min is not throttling these draws into starvation.
- Drain latency p~ buckets concentrated ≤32µs; no TX-ring stall
  signature.

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
- **Aggregate cost ≈ zero in this regime** (14.86→14.82 G): the 18G
  exact queue is cwnd-bound at ~15 G (SUM < shape, 0 retrans), so the
  "withheld surplus" EF gives up is surplus the queue was not
  achieving anyway. *This is regime-specific* — under a genuinely
  saturated exact queue EF trades aggregate for equality (the
  documented non-work-conserving tradeoff); do not generalize the
  "free" result.
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
is **not** the right *default*: (a) it is non-work-conserving by
contract (sacrifices aggregate under saturation), (b) it only halves
typical CoV and does not bound worst-case skew, and (c) the product
contract (`docs/fairness-regimes.md` Non-goals) explicitly does not
promise work-conserving equal per-flow throughput beyond `Cstruct`.
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
   CoV 12–21% — all PHYSICS with 45–65 pp margin. A 6-pile has *higher*
   Cstruct (~0.91 for `[0,0,1,2,3,6]`), so a 25% observed CoV is even
   *more* PHYSICS, not less. The verdict is monotone in the direction
   of the unobserved draw.
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
4. **Saturation labeling.** SUM ~15G < 18G shape, 0 retrans on clean
   runs ⇒ non-saturated/cwnd-bound. Gate 3 (aggregate) does not apply;
   Gates 1/2 do and pass. The "EF is free" result is therefore a
   non-saturated property — flagged in §4.

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

## 10. Codex review
_pending_

## 11. AGY review
_pending_
