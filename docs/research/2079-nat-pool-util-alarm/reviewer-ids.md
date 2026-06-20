# Reviewer task-ID ledger — #2079 (research)

| Round | Reviewer | ID / ref | Verdict |
|-------|----------|----------|---------|
| r1 | Claude SMR | claude-smr-plan-r1.md | PLAN-READY-WITH-NITS (1 MAJOR M1, refinements) |
| r1 | AGY (adversarial) | adversarial-review-mqmrffvn-smhd8t | REVISE (4 MAJOR + 1 MINOR; M1 shared-Arc double-count = critical correction) |
| r1 | Codex (codex-rescue agent) | agentId aab11e6c65bb05452 | PLAN-READY-WITH-NITS (8 findings; F1 dedup = converges with AGY M1) |
| r2 | Claude SMR | claude-smr-plan-r2.md | PLAN-READY (all r1 folds verified) |
| r2 | AGY (1st) | adversarial-review-mqmrr8na-n50emd | ENGINE TIMEOUT after full verification (no objection) — infra |
| r2 | AGY (retry) | adversarial-review-mqmrynjs-i3skz0 | PLAN-READY (all 5 r1 findings confirmed resolved) |
| r2 | Codex (1st) | agentId ab90b37ade3bef368 | INFRA-DROP (empty; after-first-job drop) |
| r2 | Codex (retry, fresh) | agentId a5710146c20086d4d | PLAN-REVISE (3 NEW MAJOR pseudocode + FOLD-5; all folded into r3) |
| r3 | Claude SMR | claude-smr-plan-r3.md | PLAN-READY (Codex NEW-1/2/3 + FOLD-5 verified resolved) |
| r3 | AGY | (pending) | (pending) |
| r3 | Codex | (pending) | (pending) |

Copilot joins only at /engineer time on the implementation PR (4th reviewer).

Infra note (`feedback_codex_infra_must_retry`): AGY r2-1st engine-timed-out
post-verification → retry PLAN-READY. Codex r2-1st infra-dropped → fresh-session
retry COMPLETED (slow, not dropped) with a substantive PLAN-REVISE — those were
REAL defects (nil-deref, prune-gap, clear-comparator, uint-cast-order), folded
into r3. r3 re-review dispatched for clean 3-way convergence (no infra excuse
relied on for the r3 gate).
