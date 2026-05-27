# Reviewer task IDs for #1605 Phase 4 plan-review

## Round 1 (plan v1 — narrow Phase 4 = rewrite JIT)
- Codex hostile plan-review: `task-mpnmsryo-txokre` — **INFRA FAIL** (codex-linux-sandbox spawn error).
- AGY adversarial plan-review: `adversarial-review-mpnmtxsi-no1clu` — VERDICT: PLAN-KILL.
- Claude SMR plan-review: `docs/pr/1605-jit-phase-4/claude-smr-plan-r1.md` — VERDICT: PLAN-KILL.

## Codex retry attempt #2 (also v1 framing)
- Codex hostile plan-review: `task-mpnnbx8x-ze7vyo` — **INFRA FAIL** again (same sandbox spawn error).

## Round 2 (plan v2 — 1M-policies framing without coordinator's Q8-Q13)
- Codex hostile plan-review: `task-mpnnkf3v-fuqmpi` — **CANCELLED** after coordinator Q8-Q13 extension superseded v2.
- AGY adversarial plan-review: `adversarial-review-mpnnkwrk-s3y24x` — **CANCELLED** same reason.
- Claude SMR plan-review: `docs/pr/1605-jit-phase-4/claude-smr-plan-r2.md` — VERDICT: PLAN-NEEDS-MAJOR (self-corrected v1 F5).

## Round 3 (plan v4 — trimmed scope on Q1-Q13 surface)
- Codex hostile plan-review: `task-mpnntgtw-njh67s` — pending.
- AGY adversarial plan-review: `adversarial-review-mpnnu0cr-h4vt3w` — pending.
- Claude SMR plan-review: `docs/pr/1605-jit-phase-4/claude-smr-plan-r3.md` — VERDICT: PLAN-NEEDS-MAJOR (drove v4 trim).

## Infra-block policy

Codex r1+r2 returned the SAME deterministic-not-transient sandbox failure
(codex-linux-sandbox spawn arg0). Per project memory
`feedback_codex_infra_must_retry`, three retries before fallback. If Codex
r3 (task-mpnntgtw-njh67s) fails identically, the methodology proceeds on
3-of-4 (Claude SMR + AGY + Copilot) per the Codex-infra-blocked exception
codified in `feedback_codex_infra_must_retry`.
