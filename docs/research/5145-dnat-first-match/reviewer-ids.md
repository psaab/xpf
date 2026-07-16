# Reviewer task-ID ledger — #5145 research

Plan doc: docs/research/5145-dnat-first-match/plan.md
Branch: research/5145-dnat-first-match

## Round 1 (plan commit 12c4a3fa156e)

| Reviewer | Mechanism | Task/Job ID | Output | Verdict |
|---|---|---|---|---|
| Codex-lane | codex:codex-rescue → shared runtime | task-mro071id-j1afrr | codex-plan-r1.md | **PLAN-KILL (Option A)** |
| AGY | agy MCP + direct CLI | adversarial-review-mro09wxr-7z8u4e / bcho814p0 | (none) | **INFRA-BLOCKED** |
| Claude SMR | in-conversation | (parent) | claude-smr-plan-r1.md → -r2.md | r1 ITERATE → **r2 PLAN-KILL** |

### Reviewer infra notes (documented retries)

- **Codex direct-companion path (task-mro09156 / -c7s3 / -edhx): infra-blocked.**
  The account is pinned to `gpt-5.6-sol` (`~/.codex/config.toml`), which the
  installed CLI (companion 1.0.6) rejects ("requires a newer version of Codex");
  model overrides `gpt-5.3-codex`, `gpt-5-codex` are account-rejected
  ("not supported when using Codex with a ChatGPT account"). 3 documented
  retries. **The `codex:codex-rescue` agent path routed through a working shared
  runtime** (job logged under the gemini plugin state dir) and produced the full
  evidence-backed review — that is the Codex-lane verdict used for convergence.
- **AGY: infra-blocked all round.** (1) `agy_adversarial_review` MCP: headless
  mode auto-denied a required `command` permission → no output. (2) Direct
  `agy --dangerously-skip-permissions --print`: "timeout waiting for response",
  no file written. 2 documented attempts. Per `feedback_codex_infra_must_retry`,
  proceed 2-of-3 (Codex-lane + Claude SMR); AGY-alone never relied on.

Research reviewers are Codex + AGY + Claude SMR (3-way). Copilot joins only at
/engineer time on the code PR (N/A — this research terminated at PLAN-KILL).
