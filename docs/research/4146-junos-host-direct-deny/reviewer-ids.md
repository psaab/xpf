# Reviewer task-ID ledger — #4146 research plan-review

Three research reviewers: Codex + AGY + Claude SMR. AGY infra-down this run
(2-of-3: Codex + Claude SMR; retry Codex on infra-block per
feedback_codex_infra_must_retry).

| Round | Reviewer | Task/Doc ID | Verdict |
|-------|----------|-------------|---------|
| r1 | Codex | task-mrdvrmz3-awcnxx (codex-plan-r1.md) | PLAN-REVISE (locus CONFIRMED; ordering/daddr/coarse-fine flaws) |
| r1 | Claude SMR | claude-smr-plan-r1.md | PLAN-REVISE (F1-F4 doc/precision) |
| r1 | AGY | INFRA-DOWN | n/a |
| r2 | Codex | task-mrdwlmyq / task-mrdx17kc-eq196p (codex-plan-r2.md) | PLAN-REVISE (5 STILL-OPEN: tiers, global-any, fine-permit, ND/PMTUD, tcp-rst) |
| r2 | Claude SMR | claude-smr-plan-r2.md | PLAN-READY (on r3) |
| r2 | AGY | INFRA-DOWN | n/a |
| r3 | Codex | (pending — re-review of r5) | (pending) |
| r3 | Claude SMR | claude-smr-plan-r3.md | PLAN-READY (r5 closes all Codex r2 items, code-verified) |
| r3 | AGY | INFRA-DOWN | n/a |

Plan revisions: r1 (8986e26d8) → r2 (69056f7bf) → r3 (25d353afc, ordered-chain +
iifname + coarse/fine + parity fixture) → r4 (334614757, concrete placement) →
r5 (single effective exact→global program per ingress; DROP-only set-subtraction,
no fine accept; fine-deny before ND/PMTUD; global-any iifname-scoped; tcp-rst
unrepresentable).
