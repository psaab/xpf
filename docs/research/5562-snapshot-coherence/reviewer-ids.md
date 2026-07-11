# Reviewer task-ID ledger — #5562 snapshot coherence

Three plan reviewers (Codex + AGY + Claude SMR). Copilot is NOT a research
reviewer — it joins at /engineer time on the implementation PR.

| Round | Reviewer   | ID / attempts                                                | Verdict            |
|-------|------------|--------------------------------------------------------------|--------------------|
| r1    | Claude SMR | in-conversation (claude-smr-plan-r1.md)                      | PLAN-NEEDS-MINOR (F1-F6) |
| r2    | Claude SMR | in-conversation (claude-smr-plan-r2.md)                      | PLAN-NEEDS-MINOR (F7) |
| final | Claude SMR | in-conversation                                              | PLAN-READY         |
| r1    | Codex      | rescue task-mrgjpyyd-jglylm; direct retries gpt-5.6-sol / gpt-5-codex / gpt-5.1-codex / gpt-5 / o4-mini | INFRA-BLOCKED |
| r1    | AGY        | rescue agent a7fc45e993a5ce185 (2 runs) + direct rescue-mrgjzkio-6nueke | INFRA-BLOCKED |

## Convergence (Claude-SMR-primary)
Both companions infra-blocked; per feedback_codex_infra_must_retry + the /research
codex-infra-blocked exception, converge on Claude-SMR-primary with the blocks
documented. Two hostile SMR rounds found and folded real findings (F1: wrong
no-Default guard; F7: classify_metadata second consumer + invalid cleanup claim),
so this was not a soft pass. Path D holds; recommendation stands.

## Codex infra-block
CLI 1.0.6 + ChatGPT account: default `gpt-5.6-sol` requires a newer CLI; all other
probed models rejected ("not supported when using Codex with a ChatGPT account").
5 retries.

## AGY infra-block
agy companion went off-task on all 3 invocations (hallucinated `--print-timeout`
CLI-flag docs, never read plan.md or any cited source). Known "companion CLI lost
results" mode. No usable verdict.

Re-attempt both at /engineer time; Copilot joins as 4th reviewer on the code PR.
