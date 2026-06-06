# #1760 stage-2 structural fix — reviewer ledger

Stage-1 counter: merged #1762 (da85a8127). Live incidence: 0 (loss cluster, interface-SNAT).
Operator chose: engineer stage-2 despite 0 incidence.

## Round 1 (v1) — pending
- Codex r1: task-mq20vwct-q2e58v
- AGY r1: adversarial-review-mq20wbyx-ii4fqo
- Claude SMR r1: claude-smr-plan-r1.md (PLAN-NEEDS-MAJOR on §7 HA divergence; §2 validated)

## Round 1 (v1 @10493704f)
- Codex r1: task-mq20vwct-q2e58v — PLAN-NEEDS-MAJOR bordering KILL (shared map + sync replay + disposition + liveness)
- AGY r1: adversarial-review-mq20wbyx-ii4fqo — PLAN-NEEDS-MINOR (lifecycle gap; owner-RG unsafe; §2 airtight)
- Claude SMR r1: claude-smr-plan-r1.md — PLAN-NEEDS-MAJOR (HA divergence)
- v2 folds: node-level refusal (owner-RG dropped), shared-map guard, real drop disposition, displaceable-incumbent predicate, key_to_handle fallback, publish-path determinism argument

## Round 2 (v2) — pending
- Codex r2: task-mq21h0of-mwuoqd
- AGY r2: adversarial-review-mq21h0zr-pvh7px
- Claude SMR r2: claude-smr-plan-r2.md (PLAN-NEEDS-MINOR — pin Q2 keep-both)
