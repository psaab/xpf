# Reviewer ledger — #5488 research plan

Three research reviewers (Claude SMR + Codex + AGY). Copilot joins at
`/engineer` on the code PR (not a research reviewer).

## Claude SMR (primary)
- r1: `claude-smr-plan-r1.md` — VERDICT **PLAN-READY-WITH-REQUIRED-REVISIONS**.
  Found F1 (three-generation v3 collision) + F2 (symmetric helper-first skew).
  Both folded into plan **r2**.

## Codex (gpt-5.6-sol via codex-cli 0.144.0)
- Model note: the explicitly-named models (`gpt-5`, `gpt-5.1`, `gpt-5-codex`,
  `gpt-5.1-codex`, `o3`) are ALL rejected with a ChatGPT account
  ("model is not supported when using Codex with a ChatGPT account"). The
  DEFAULT model resolves to `gpt-5.6-sol` and WORKS (probed with a live
  `codex exec` round-trip → `CODEX_OK`). So Codex is NOT infra-blocked on this
  host with the default model — the team-lead's "CLI 1.0.6 / gpt-5.6-sol needs a
  newer CLI" note does not match this host (0.144.0 runs gpt-5.6-sol fine).
- r1 attempt: hostile plan review launched via `codex exec` (prompt at
  `/tmp/codex-5488-plan-review-prompt.txt`). Codex performed a deep source
  exploration (read policies_lower.go, snapshot.rs, policy.rs, security.rs,
  manager_*.go) but the ultra-effort run did not converge to a verdict within
  its turn budget on the first attempt. Retried with a verdict-first prompt.
  See `codex-plan-r1.md` for the captured result.

## AGY (antigravity-cli 1.1.1)
- r1: `agy_adversarial_review` job `adversarial-review-mrgnrkw9-i813ai` →
  **FAILED / OFF-TASK.** AGY did not review the plan; it went off and researched
  an unrelated `--print-timeout` CLI flag, then died with
  `agy stdin write failed: write EPIPE`. Consistent with the project's standing
  note that AGY is low-signal / off-task on review tasks
  (`feedback_review_file_signal_codex_vs_agy`, `feedback_agy_writes_code_during_review`).
  DOCUMENTED as blocked for `/engineer`-time re-attempt. AGY alone is never
  sufficient; convergence proceeds on Claude SMR (primary) + Codex.

## Convergence policy
Per `/research` SKILL + `feedback_codex_infra_must_retry`: the research quad is
Codex + AGY + Claude SMR. With AGY off-task/blocked (documented, retryable at
`/engineer` time), convergence is Claude-SMR-primary + Codex (2-of-3). AGY is
re-attempted on the implementation PR.
