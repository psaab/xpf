# Claude SMR hostile plan review — round 1

**Plan:** `plan.md` @ `c7ef5a3fe`
**Verdict: PLAN-READY** (with two refinements below — neither blocks)

I independently verified the load-bearing facts (not just the workflow
verifiers): `.configdb/` is flat (configstore/db.go — active/candidate/
rollback.N.json, journal is a sibling `.config.journal`); `parseSyncEstablished`
gates draining (cluster_cli.go:119, kernel_drain.go:124, rolling.go:101/168);
`FormatInformation` emits `Status:` once (cluster/status.go:248) with
`FormatIPMonitoringStatus` separate; store.go is 2011 LOC. The plan's two
central conclusions hold:

1. **Both Part I findings are LATENT, not live bugs.** AGY over-stated them as
   active systems bugs; they cannot fire on the current tree. Downgrading to one
   LOW defensive-hardening issue (#1968) is the correct, honest call — and the
   fixes still earn their keep as future-proofing (the included tests prevent
   the latent cases from silently going live).
2. **Part II is correctly KILL/DEFER.** Every target is under the project's own
   2000-prod-LOC modularity threshold; kernel_*.go and configstore/secure are
   already file-decomposed (the proposals are namespace churn, and kernel_*'s
   "~1937" is a sum of already-separate files); wg_control/tunnel_supervision
   are hot-path/cohesive with no measured perf case (the #1207 precedent killed
   exactly this). Not filing refactor issues is right — don't create issues just
   to kill them.

## Why this is an honest PLAN-READY, not a soft pass

The SMR-soft-pass warning is noted. I actively looked for a reason to fail this
and the strongest counter-arguments don't hold:
- *"Under-threshold files can still warrant decomposition for testability."*
  True in principle, but the per-target assessment found no testability gap the
  current structure can't address, and the one plausible perf case (wg_control
  I-cache) is unmeasured — DEFER (revisit-with-data), not PLAN, is correct.
- *"store.go @ 2011 should be a filed decomposition issue now."* It's only
  marginally over and the fortnightly modularity audit already exists to catch
  it — filing now would pre-empt the audit's own judgement. Deferring is right.

## Refinement 1 — make AGY-I-2's conditional severity explicit

The plan calls AGY-I-2 LOW. The *failure mode* (drain a node with a Down sync
link → cluster connection drops) is genuinely MEDIUM-class; it is LOW only
because it cannot fire today (single `Status:` in `FormatInformation`). State
this conditionally: **LOW now, MEDIUM the moment any pre-sync section with
`Status:` is folded into `FormatInformation`** — which is exactly why the
"assert exactly one `Status:`" test is the load-bearing part of the fix (it
fails loudly the day someone introduces the collision). Lead with the test.

## Refinement 2 — note the KILL has no issue to label

Per `feedback_plan_kill_label_required`, a PLAN-KILL normally closes/labels the
issue. Here Part II has **no filed issues** (correctly), so the KILL is a
documented recommendation in this plan + the issue comments, not an issue-state
change. Say so explicitly so the convergence record is unambiguous.

## To finalize
Fold the two refinements (both one-liners). The plan is otherwise ready: Part I
→ #1968 PLAN-READY direction; Part II → KILL/DEFER ratified.
