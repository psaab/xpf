# Companion review status — #6102 plan

Research contract: hostile reviews from Claude SMR + Codex + AGY.

| Reviewer | CLI reachable | Verdict | Notes |
|----------|---------------|---------|-------|
| Claude SMR | n/a | **PLAN-READY** | `claude-smr-plan-r1.md`; 5 findings (F1 MED-for-PR, F2–F5 LOW/INFO), none block the plan. |
| Codex | yes (`codex-cli 0.144.0`) | **BLOCKED** | Infra-blocked: default model `gpt-5.6-sol` requires a newer Codex CLI/app (`400 invalid_request_error … requires a newer version of Codex`). Reproduced identically on one retry. No review produced. |
| AGY | yes (`agy 1.1.4`) | **MISFIRED (no review)** | Job exited 0 but did not perform the requested adversarial review — it returned unrelated documentation about the `agy --print-timeout` flag instead. Consistent with the project's known low AGY plan-review signal. No usable verdict. |

**Converged pass: 1-of-3 (Claude SMR = PLAN-READY).** Both companions
failed to deliver a real hostile review — Codex infra-blocked (one retry,
same 400), AGY off-task. Per the `/research` contract this is documented
and the SMR stands as the converged adversarial pass. The 5 SMR findings
(F1–F5) are carried to the `/engineer` pass; none block PLAN-READY.
