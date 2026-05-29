# Reviewer task IDs — #1653 external review triage

Per `feedback_codex_session_loss_continuation`: record task IDs so continuations
can fetch by id rather than re-dispatch.

## Round 1

- **AGY**: `adversarial-review-mpqfw6se-tn1uo0` (DIED — stuck queued, never started; agy_status falsely reported "succeeded"). Re-dispatched as `adversarial-review-mpqgda9b-cwn2ka`.
- **Codex**: gpt-5.5 (account rejected gpt-5.1-codex / -codex-max), read-only sandbox, /tmp/codex-1653-out.txt. First two attempts failed on unsupported model names; default-model attempt is the live one.
- **Claude SMR**: `claude-smr-plan-r1.md` (this branch) — PLAN-READY-WITH-NITS (3 MINOR refinements, all folded into r1). No misclassification found on independent re-verification.

### Convergence

All three reviewers: **PLAN-READY-WITH-NITS**. No misclassification found; no real
bug downgraded. Nits folded into plan r2:
- §1.2: "compile error at construction site" → corrected to "exhaustive matches"
  (Codex); the 2 service.rs guards match `ExactCoSScratchBuild` (3-variant), not
  `CoSPendingTxItem` (AGY).
- §1.7: `make_mut` isn't even a drop-in (inner types not `Clone`) (Codex).
- §2.3: 36 params, not ~37 (Codex).

- **Codex** (gpt-5.5): `codex-plan-r1.md` — PLAN-READY-WITH-NITS, 127k tokens.
- **AGY**: `agy-plan-r1.md` (job adversarial-review-mpqgda9b-cwn2ka) — PLAN-READY-WITH-NITS.
- **Claude SMR**: `claude-smr-plan-r1.md` — PLAN-READY-WITH-NITS.

Umbrella: #1653
Branch: research/external-review-triage
Plan: docs/research/external-review-triage-2026-05-28/plan.md @ r2
