# Reviewer task-ID ledger — #4146 research plan-review

Three research reviewers: Codex + AGY + Claude SMR. AGY infra-down for this run
(Codex + Claude SMR, 2-of-3; retry Codex on infra-block per
feedback_codex_infra_must_retry).

| Round | Reviewer | Task/Doc ID | Verdict |
|-------|----------|-------------|---------|
| r1 | Codex | task-mrdvrmz3-awcnxx (codex-plan-r1.md) | PLAN-REVISE (locus CONFIRMED; ordering/daddr/coarse-fine flaws) |
| r1 | Claude SMR | claude-smr-plan-r1.md | PLAN-REVISE (F1-F4 doc/precision; folded r2) |
| r1 | AGY | INFRA-DOWN | n/a |
| r2 | Codex | (pending — re-review of r3) | (pending) |
| r2 | Claude SMR | claude-smr-plan-r2.md | PLAN-READY (r3 folds all findings) |
| r2 | AGY | INFRA-DOWN | n/a |

Plan revisions: r1 (8986e26d8) → r2 (69056f7bf, folds SMR F1-F4 + scheduler) →
r3 (rework: ordered-chain projection + iifname ingress scope + coarse-then-fine
+ parity fixture + all Codex plan-r1 hazards).
