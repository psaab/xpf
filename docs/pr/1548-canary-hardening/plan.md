# #1548 conntrack: harden legacy_dataplane_canary against alias / import-rename / dot-import bypasses

**Status:** PLAN-KILL v1 — closed without implementation per converged adversarial-review verdict

## Outcome

This plan was killed at round 1 of adversarial review. The verdicts:

- **AGY** (`adversarial-review-mple2451-ezsc8h`): **PLAN-KILL** — value <
  churn given imminent retirement of `pkg/dataplane.DataPlane` via
  #1476/#1528. Sibling migrations (#1517 cli, #1518 cluster session-
  sync) merged the same day this plan was drafted. Hostile-developer
  threat model unrealistic (a developer with commit access who wants
  to bypass the canary can delete the file).
- **Codex** (`task-mple1mix-ygr7w6`): **PLAN-NEEDS-MINOR** — would
  not kill, but every MINOR finding is a *scope reduction*: drop
  alias hardening (already caught by pass-2), drop dot-import
  identifier sweep (false-positive risk), keep only import-rename
  detection + dot-import declaration-fire. Net value after reductions:
  ~30-50 LOC for a fence whose subject type will be deleted by
  #1476 in the near future.

The converged read across both reviewers: **the existing pass-2
catch-all selector sweep that shipped with #1532 already catches
every honest-refactor reintroduction.** What remains uncaught is
deliberate evasion via import rename or dot import — a threat
model that's neither realistic for this codebase nor durable past
#1476's landing.

Both reviewers independently confirmed the plan's reading of the
existing canary's coverage (compound types, generic constraints,
generic instantiations, type-alias declarations all caught by
pass-2 today). The remaining bypasses (import rename, dot import,
transitive alias use, cross-package wrapping) all share a single
property: the literal `dataplane.DataPlane` selector is absent
from the AST, so AST-only walking cannot resolve them. `go/types`
could, but adding a typed-package loader to a unit-test canary
that will be deleted within the retirement window is the wrong
trade.

## Decision

**Close #1548 with rationale.** The acceptable PLAN-KILL outcome
explicitly named in the project's standing rules (`feedback_auto_
merge_on_clean_triple`'s sibling `AGY may PLAN-KILL on "wasted
churn pre-#1528/#1476" rationale`) is the right call here.

If #1476 slips materially (e.g., several months past current pace),
revisit — the value window would re-open. Re-opening should adopt
Codex's reduced scope (import-rename + dot-import-decl only, no
alias hardening, no identifier sweep).

## Verbatim verdicts (preserved for the record)

### Codex `task-mple1mix-ygr7w6`

> Verdict: **PLAN-NEEDS-MINOR**. I would not kill it, but I would
> not send implementors from this plan unchanged.
>
> - MEDIUM: Dot-import design is internally inconsistent. (...)
>   Pick the declaration-level fire. A scoped ident sweep will
>   false-fire on local `type DataPlane int`, local type params,
>   or local declarations shadowing the dot import unless it
>   becomes a scope/type checker.
> - MEDIUM: Phase 3 alias hardening is overstated. Same-package
>   alias declaration already fails because pass 2 sees
>   `type DPAlias = dataplane.DataPlane`. (...) The same-file
>   Option-B scan adds diagnostics, not real enforcement (...).
> - MEDIUM: Pure AST is acceptable only if you stop claiming
>   hostile-developer coverage. (...) Given this is a short-lived
>   test fence, I would keep AST, but frame the PR as
>   lightweight import-rename/dot-import hardening, not
>   deliberate-evasion proof.
> - LOW: Smoke scope wording is wrong. This is not
>   `docs-only-skip-smoke`; it edits Go test code. (...) Use a
>   test-only/no-prod-change rationale, not a docs-only marker.
>
> Value vs churn: not PLAN-KILL from local evidence. `origin/master`
> has #1518 and #1520 merged; #1519 was PLAN-KILLed pending
> capstone; #1516 has a MERGE-READY branch but is not on
> `origin/master`; #1521 is active but not merged; #1528 is
> plan-only.
>
> Sibling canaries: keep out of this PR. Copy the final pattern
> later.

### AGY `adversarial-review-mple2451-ezsc8h`

> Verdict: PLAN-KILL.
>
> Rationale 1 (Value vs. Churn): #1528 (DPDK mechanical removal)
> actively in progress; #1476 (eBPF mechanical removal) sibling
> migrations already merging (e.g., #1518 has introduced
> SetRuntime decoupling pkg/cluster/sync.go from
> dataplane.DataPlane). Once #1476 is merged, dataplane.DataPlane
> will be deleted from the codebase. At that point, the Go
> compiler itself becomes the absolute, unbreakable regression
> fence. Introducing ~80-130 LOC of complex AST-parsing logic
> for dot-imports and aliases is transient busywork that will
> be deleted along with the type in the near future.
>
> Rationale 2 (Threat Model): If a developer has commit access
> and is deliberately trying to reintroduce the prohibited type,
> they can simply: (1) delete the canary file, (2) add their
> file to the skip list, (3) wrap the interface or use empty
> interface casting (`interface{}`) and reflection to erase the
> static type entirely from the AST.
>
> Rationale 3 (Syntactic vs Semantic mismatch): Option B
> (same-file alias scan) is blind to cross-file alias
> definitions. Dot-import identifier sweeps risk false positives
> on unrelated local variables, fields, or helper functions
> named DataPlane unless `go/types` is used.
>
> Rationale 4 (Sibling Canary Vulnerability): Plan marks sibling
> canaries (#1516, #1517, #1518) OUT OF SCOPE. This creates an
> inconsistent posture: we would spend significant effort
> hardening pkg/conntrack while leaving the other three packages
> vulnerable to the exact same "bypasses."
>
> Verification of Plan Claims: 100% correct. Compound types,
> generic constraints/instantiations, and type-alias declarations
> are all caught by Pass-2 today. Confirmed by reading
> [legacy_dataplane_canary_test.go] lines 308-310, 230, 238-244.
>
> Summary Recommendation: Do not proceed with the implementation
> of #1548. The existing canary on `master` is fully sufficient
> to catch accidental refactoring errors by honest developers.
> Engineering effort should be redirected to accelerating the
> completion of #1476 and #1528 to delete the legacy interface
> permanently.
