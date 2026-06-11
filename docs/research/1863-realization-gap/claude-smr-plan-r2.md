# Claude SMR plan review — #1863 round 2 (plan v3 @ 0b209c7a4)

## Self-correction (round-1 SMR error)

My r1 finding 1 cited #1691's 22.72 G as a PUSH aggregate with CoS;
Codex r1 F5 showed it is a REVERSE-direction sanity number
(`docs/pr/1691-cos-push-ceiling-gate-rescope/plan.md:113-118`,
`docs/fairness-regimes.md:1296-1300` — re-verified directly). v3
removes the citation and demotes the aggregate gate to secondary
(per-class mid gates primary, ≥20.5 G aggregate vs 19.6 demonstrated).
This is the correct repair: the gate no longer rests on an
unsupported reachability claim.

## v3 fold verification (all round-1 findings, cross-checked)

- Codex F1 → §3 leg 3 now carries the CoS-cost caveat; the
  work-conservation proof correctly rests on the +9g leg. DONE.
- Codex F2 / my F2 / AGY F2 → §2.5 reworded to worker-pooled
  implication; Step-0 per-class instrument mandatory with a
  registered (a)/(b)→A-ii/B decision rule. DONE.
- Codex F3 / my F3 → admission-drop counter family added to the
  Step-0 capture contract (verified `admission.rs:218-222`:
  `buffer_limit` scales with `buffer_bytes.max(COS_MIN_BURST_BYTES)`
  — the confound is real and now disclosed). DONE.
- Codex F4 / AGY F1 → A-i rejected with the ClassCap-race trace
  (`shared_cos_lease/mod.rs:1396-1398` — re-verified); A-ii lead
  with isolation/equal-flow/carry-bounding conditions. DONE.
- Codex F6 → raw/MANIFEST.md present; labels match the session
  record (I cross-checked p6g-r3 and s24-r1/r2 against the
  timestamps + journal evidence). DONE.
- AGY F3 / my Q4 → burst/8 hygiene decoupled with latency-focused
  validation (sojourn 23.0→9.6 ms recorded). DONE.

## Residual judgment

The plan's load-bearing chain is now: kill-exit closed (arithmetic +
9g work-conservation + bounded ceiling) → selector layer falsified
as rate-setter (cell P, registered prediction) → supply-side proven
(udp3g inelastic) → lease claim path implicated (worker-pooled
grants tracking, strict-share code trace) → Step-0 instrument
resolves the final (a)/(b) attribution BEFORE code, with a
registered branch to A-ii or B. Every inferential step is either
measured, code-quoted, or explicitly deferred to a pre-registered
instrument. The remaining risks (CPU feedback, equal-flow
interaction, carry bounding) are named with gates.

## Verdict

**PLAN-READY** (round 2). No new findings.
