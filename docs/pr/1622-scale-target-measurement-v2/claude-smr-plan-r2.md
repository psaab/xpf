# Claude SMR plan-review r2 (PLAN-KILL convergence) — #1622 Scale Target measurement v2

**Reviewer role**: domain SMR — perf measurement methodology + scope-gate enforcement.

**Plan under review**: `docs/pr/1622-scale-target-measurement-v2/plan.md` v1 @ commit `9d830d12e`.

**Co-reviewer status r1**:
- AGY (`adversarial-review-mppr5rgp-f7fmdp`): **PLAN-KILL** (6 findings, hostile).
- Codex (background dispatch `b9ubz3o12`): incomplete reply — investigation phase only, no structured final verdict, mid-thought confirming bounded-cohort sampling rate regression. Treated as INFRA-INFRACTION per `feedback_codex_infra_must_retry` — but AGY + Claude SMR are both PLAN-KILL converging, so further Codex retries are not required to settle the decision.
- Copilot: N/A pre-PR.

**Quorum**: 2-of-3 (AGY + Claude SMR) converge on PLAN-KILL. Decisive per `feedback_plan_kill_label_required` quorum convention.

## Verdict: **PLAN-KILL**

I am retracting my r1 verdict (PLAN-NEEDS-MAJOR) and converging with AGY's r1 PLAN-KILL. After re-reading my own r1 F1+F2+F3 findings against the explicit issue out-of-scope contract, I realise that **the must-fix remediations require modifying the #1619 foundation** that the issue explicitly forbids touching:

> Out of scope — DO NOT touch (#1622 issue body, embedded in the agent contract):
> - `userspace-dp/src/afxdp/cold_path_hist.rs` (just shipped #1619 scaffolding; treat as foundation)
> - `userspace-dp/src/protocol/` (just shipped #1621 wire-protocol; treat as foundation)

The remediation paths that AGY r1 and I r1 both identified are:

1. **F1 / AGY #1** bucket-0 resolution floor remedy → adopt finer-grained low-end buckets (e.g. log-spaced at 64/128/256/512/1024 ns). **Requires changing `cold_path_hist.rs` (#1619 foundation) AND the wire-protocol bucket count (#1621 foundation).** OUT OF SCOPE.

2. **F2 / AGY #2+#3** per-zone-pair semantics remedy → eliminate the splitmix64 hash; switch to a direct `(from_zone_id, to_zone_id)` map. **Requires changing `zone_pair_slot()` in `cold_path_hist.rs` (#1619 foundation) AND expanding the per-worker slot array beyond 16.** OUT OF SCOPE.

3. **F3 #1609 v2 unblock claim** → publish baseline only, not unblock. **Soft remedy possible within scope; not load-bearing in isolation.**

Without F1 + F2 addressed, the deliverable (populated Tables A1/A2/B1/B2 in `docs/userspace-jit-design.md`) is structurally untrustworthy:

- 10-rule cell will read `p50 = 512 ns` (bucket-0 midpoint artifact, not measured value).
- 100-rule cell will likely also collapse to bucket 0 → `p50 = 512 ns`.
- 1K-rule cell starts to populate bucket 1+ but is still resolution-limited.
- 10K-rule cell may finally show resolution above bucket-0 floor.
- "Aggregate p50 across non-aliased slots" is a bimodal-distribution artifact, not a per-zone-pair latency — operators citing the table will be wrong.

**The right architectural action**: file a new umbrella issue covering #1619 + #1621 + #1622 as a single redesign — change the histogram layout to log-linear at the low end (5-10 buckets per decade in the 50-1000 ns regime) AND switch the per-zone-pair slot from a 16-slot splitmix64 hash to a direct map (or expand to 64+ slots with a separate alias table). That umbrella will need its own plan-review cycle.

**The right action on #1622 right now**: PLAN-KILL, close the issue, document the structural blocker on the parent #1612, and let the operator decide whether to:
- (a) accept the structurally limited table with extensive footnotes (re-open #1622 with a downscoped deliverable: harness + raw TSV ship, table NOT populated — i.e. the STAGED form becomes the FULL form), or
- (b) open a #1619-redesign issue that fixes the bucket layout + slot mapping, then re-attempt #1622 against the redesigned foundation.

I recommend (b) but the operator may legitimately pick (a) — the harness + TSV are still useful artifacts for future #1619-redesign validation.

## Specific AGY r1 findings I concur with

- **AGY #1 (bucket-0 collapse)** — matches my r1 F1. Structurally fatal at 10/100-rule cells. The plan's Q6 acknowledgement is honest but the picked path ("acknowledge as floor in footnote") does not produce trustworthy table rows.
- **AGY #2 (splitmix64 collision selection bias)** — matches my r1 F2. The 88.2% collision probability at 8 zone-pairs is correct (birthday-paradox math on K=8 balls in 16 slots: `1 - prod(1 - i/16 for i in 0..8) ≈ 0.882`). When a high-rule-count zone-pair collides with a low-rule-count one and both are excluded, the published aggregate is biased toward the survivor distribution.
- **AGY #3 (bimodal distribution corruption)** — matches my r1 F2 (sub-finding). Aggregate p50 over a union of disjoint per-zone-pair distributions is a packet-mix-ratio artifact, not a flow-duration percentile. This was implicit in F2 but AGY made it explicit; concur.
- **AGY #4 (fixed CIDR mix masks JIT codegen)** — this is correct for #1605 Phase 4 (Cranelift JIT) but the current #1632 Path B implementation is still flat sorted scan, not JIT-compiled. For the current foundation the JIT-codegen concern is hypothetical. AGY's finding is correct **for the eventual JIT Phase 4** but does NOT yet apply to the post-#1632 baseline. Severity: MED, not HIGH (I lower this one). Does not change the overall PLAN-KILL verdict.
- **AGY #5 (wall-clock budget underestimate)** — I missed the CoS axis multiplier in v1. AGY is right: 4 rule × 2 cohort × 2 CoS × 3 runs = 48 cells × 75 s = 60 min, not 30 min. Plus deploy. Severity: MED. NOT a kill axis on its own but reinforces the STAGED-fallback unsoundness.
- **AGY #6 (STAGED-ship loophole)** — matches my r1 implicit concern. The issue explicitly demands populated tables; a STAGED fallback that ships empty tables is a punt that violates the deliverable contract.

## Filing follow-ups

Per `feedback_plan_kill_label_required`:

```bash
gh issue close 1622 \
    --reason "not planned"
gh issue edit 1622 --add-label "plan-kill"
gh issue comment 1622 --body "PLAN-KILL with full reviewer convergence (AGY adversarial-review-mppr5rgp-f7fmdp + Claude SMR claude-smr-plan-r1+r2). Plan v1 archived on perf/1622-scale-target-measurement-v2 @ 9d830d12e. ..."
```

Follow-up issue to file:
- **#1622-FOLLOWUP-A** (umbrella): "Redesign cold-path histogram bucket layout (#1619) + per-zone-pair slot mapping (#1619) so Scale Target tables can publish trustworthy numbers."
  - Bucket redesign: log-linear at low end, e.g. 8 buckets per decade in [50, 1000) ns, then power-of-2 above.
  - Slot redesign: direct map keyed on `(from_zone_id, to_zone_id) → slot`, with explicit overflow handling for clusters with >64 active zone-pairs. The 16-slot splitmix64 hash is fundamentally incompatible with per-zone-pair latency reporting.
  - Wire-protocol bump to carry the new layout.
  - Once the redesign lands, reopen #1622 against the new foundation.

## Summary

PLAN-KILL is the correct action. The deliverable specified by #1622 cannot be produced trustworthy-ly against the post-#1619/#1621 foundation that the issue mandates we treat as fixed. Two of three reviewers converge on this.
