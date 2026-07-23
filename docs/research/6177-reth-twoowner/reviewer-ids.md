# Reviewer ledger — #6177 research plan

Three research reviewers: Claude SMR + Codex + AGY. Copilot is NOT a research
reviewer (joins the quad at `/engineer` on the code PR).

| Round | Reviewer | Mechanism | Artifact | Verdict |
|-------|----------|-----------|----------|---------|
| r1 | Claude SMR | in-conversation hostile pass | `claude-smr-plan-r1.md` | PLAN-NEEDS-REVISION (SMR-1..7) |
| r1 | Codex | `codex exec` medium effort (foreground) | timed out at 10m mid-spelunk — retried | (no verdict) |
| r2 | Codex | `codex exec` medium effort, fact-front-loaded, background | `codex-plan-r2.md` | (pending) |
| r2 | AGY | `agy` adversarial | — | INFRA-DOWN (best-effort per feedback_gemini_infra_outage_merge_policy) |
| r2 | Claude SMR | in-conversation re-review of r2 | `claude-smr-plan-r2.md` | (pending) |

Convergence rule: Codex + Claude SMR must agree (PLAN-READY or PLAN-KILL). AGY
infra-down → 2-of-3 SMR-primary with documented retries (research SKILL standing
rules + feedback_codex_infra_must_retry). AGY alone is never sufficient; here it is
Codex + Claude SMR.
