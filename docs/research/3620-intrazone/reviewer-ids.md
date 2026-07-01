# Reviewer ledger — #3620 intrazone /research

Three research reviewers: Codex + AGY + Claude SMR (Copilot joins only at
`/engineer` on a code PR — not applicable to a docs-only research plan).

| Round | Reviewer | Task/Job ID | Verdict | Artifact |
|-------|----------|-------------|---------|----------|
| r1 | Claude SMR | (in-conversation) | PLAN-KILL-CONFIRMED | `claude-smr-plan-r1.md` |
| r1 | AGY | agy print-mode job `bmdukyfkt` (bg) | PLAN-KILL-CONFIRMED | `agy-plan-r1.md` |
| r1 | Codex | `task-mr1rslvt-ra3ovj` (companion registry dropped the job — fetch-by-id "No job found", the documented Codex infra-drop); re-run via `codex:codex-rescue` agent for inline capture | see `codex-plan-r1.md` | `codex-plan-r1.md` |

Notes:
- Codex-infra-blocked exception (research skill): if Codex is infra-blocked,
  proceed 2-of-3 (Claude SMR + AGY) with documented retries. AGY alone is never
  enough. Here Claude SMR + AGY both PLAN-KILL-CONFIRMED; Codex re-dispatched via
  the rescue agent to reach full 3-of-3.
