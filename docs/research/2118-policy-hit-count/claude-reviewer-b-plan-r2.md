# Hostile Claude reviewer B — plan-review r2 (on plan r2)

Verdict: **PLAN-READY** (with re-rank + caveat edits) → folded into r3.

Independently traced the full increment→snapshot→wire→read→display chain
against source. The plan's central thesis (chain intact; bug is live-only
diagnosis + gating-unification) is CORRECT and well-supported. No concrete
break found in the code. Option A is the right direction; wire reuse is
#1961-safe; hot path clean (one relaxed atomic on the cold path, no
packet-path lock); preserve-on-recompile is a defensible documented
divergence.

## MAJOR (re-rank / evidence, no new work)
- Cited smoke doc `docs/smoke/security-matrix-2026-06-20.md` does not exist
  in branch or origin/master. The concrete numbers survive (Policy deny
  0→8/0→6). Note the doc is missing; Step 1 is the authoritative evidence.
- H2 is the PRIMARY cause for the DENY rows, not a tied fallback: aggregate
  `policy_deny` fires on default-deny (mod.rs:1732) while the per-rule
  counter increments only on an explicit match (policy.rs:1067); the
  default path (policy.rs:959) increments nothing. The cluster config
  (ha-cluster-userspace.conf:176) has zero explicit deny rules → per-rule
  0 on the deny side is CORRECT. Direct Step 1 at the explicit-PERMIT rows.

## MINOR
- Option B rejection rationale imprecise: policies.go:47 is a positional ID
  `policySetID*MaxRulesPerPolicy + ruleIndex`, not an "app-term expansion
  step". The stability argument (positional IDs shift on reorder) still
  rejects B; fix the justification.
- The implicit-deny count (§6 Step 2 / §8) must NOT use `rule_hit_counter("")`
  (empty RuleID is skipped by buildPolicyRuleCounterIndex,
  policycounters.go:16-18) — it needs a SEPARATE synthetic counter. State
  the requirement so Step 2 doesn't route it through the keyed store.
- Preserve-on-recompile vs Junos reset: keeping the more-useful behavior +
  documenting in docs/feature-gaps.md is right; ensure the issue records it
  as a decision.
- Step 3 gate unification will not break M4 (all three surfaces share the
  policyCounterID formula; Prometheus already gates; existing metrics_test
  unaffected). Mirror the gate test for the text paths (already in §8).

## Note on reviewer A's "per-packet" concern
Verified mod.rs:2342 is the cold path; it does NOT seed a session, so for
an unresolved-neighbor flow it re-evaluates per packet until the neighbor
resolves — a TRANSIENT over-count, not steady-state. r3 states it as
transient and adds the invariant test.

## Resolution in r3
H2 promoted to primary for deny rows; missing-smoke-doc caveat added;
Option-B file:line corrected; synthetic-counter requirement added; second
site + transient over-count documented; preserve-on-recompile decision to
be recorded in the issue comment.
