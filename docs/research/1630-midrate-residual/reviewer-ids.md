# #1630 cause-2 (mid-rate residual) — reviewer task IDs

Research mode: 3-way plan review (Codex + AGY + Claude SMR). Copilot
joins at /engineer on the implementation PR.

Record task IDs here so continuations can fetch by id (per
`feedback_codex_session_loss_continuation`).

| Round | Reviewer | Task ID / Session | Verdict |
|-------|----------|-------------------|---------|
| r1 | Codex | codex exec (read-only sandbox), prompt /tmp/codex-1630-c2-r1.txt | **PLAN-NEEDS-MAJOR** (BLOCKING-1 head_len-not-quantum; BLOCKING-3 consumed≠TX; MAJOR-1/2/3; BLOCKING-2 HALLUCINATED waterfill — rejected w/ grep) |
| r1 | AGY | `adversarial-review-mpqbvucd-8txj5t` (succeeded; agy_result MCP timed out 3×) | result infra-blocked; investigation trace converged on the head_len park-basis defect → aligned PLAN-NEEDS-MAJOR (see agy-plan-r1.md) |
| r1 | Claude SMR | docs claude-smr-plan-r1.md | **PLAN-NEEDS-MAJOR** (concur Codex B1/B3 + M1/2/3; reject B2 with grep; +3 own: corrected-magnitude-unknown, 3-way bisection, H-TCP) |

## r1 convergence

2-of-3 decisive PLAN-NEEDS-MAJOR (Codex + Claude SMR, both quoted-line
evidence; AGY infra-blocked but trace-aligned). Per
`feedback_codex_infra_must_retry`: Claude SMR + Codex are both real and
decisive, satisfying "Claude SMR + one external real." Codex BLOCKING-2
(waterfill drain path) rejected as a verified hallucination — NOT folded
in. v2 folds B1/B3/M1/M2/M3 + the 3 Claude findings.
