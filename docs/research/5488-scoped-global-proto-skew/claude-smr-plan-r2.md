# Claude SMR — plan review r2 (convergence) (#5488)

Reviewing plan **r3** (F1/F2 folded from SMR r1; Codex nits #5/#6 folded).

## Verdict

**PLAN-READY on Path C.** My r1 required-revisions (F1 three-generation v3
collision, F2 symmetric skew direction) are now in the plan (§3 gen table, §5
per-generation robustness table + symmetric-direction paragraph, §11 Q8–Q9).
Codex's independent hostile pass reached the same conclusion (PLAN-READY-WITH-
NITS, Path C) and its findings 1–4 corroborate F1/F2/F3/F6 and reachability;
its two nits (#5 effective-coverage test, #6 plural-as-authoritative wording)
are folded into r3. No open reviewer disagreement remains.

## Residual scope, stated for the record (not blockers)

- Path C discharges the #5488 invariant (deny/reject coverage) **completely and
  robustly across all three v3 helper generations** — my hostile pass and
  Codex's both failed to find any verdict/ordering that makes the deny/reject
  widening fail-open.
- Path C does NOT close two ADJACENT, PRE-EXISTING holes (documented as
  non-regressions, out of #5488's deny-coverage scope): the symmetric
  helper-first skew (old Go → gen3 helper still narrows the deny) and the gen1
  scoped-*permit* over-permit. Only Path A (version bump) closes those, at the
  #5364 all-config flag-day cost. This is surfaced as §11 Q8/Q9 for the user's
  values call at `/engineer` time — it does not block PLAN-READY.

## Recommendation to the user

Ship **Path C** (version-free per-verdict safe lowering) — it converts the named
fail-open into a fail-closed with zero wire/version/deploy cost and no #5364
deploy-crossing wall. If, at `/engineer` time, the team decides complete
bidirectional skew safety (both directions + gen1 permit) is worth a coordinated
flag-day, escalate to Path A as a separately-tracked protocol-versioning cleanup
(the hybrid noted in §5). AGY is off-task/blocked (documented in
reviewer-ids.md) and re-attempts on the implementation PR alongside Copilot.
