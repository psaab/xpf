# Reviewer task-ID ledger — #5865 research plan

Plan doc: `docs/research/5865-session-schema/plan.md`
Branch: `research/5865-session-schema`

## Round 1 (plan v1 @ 9238c85010c8)

| Reviewer | Mechanism | Task/Job ID | Status |
|---|---|---|---|
| Codex | codex-companion task --background | `task-mro3zu2r-1snnkf` | running (deep verify) |
| AGY | agy-companion adversarial-review | `mro438va` / `mro46wdv` / `mro47h4p` | **INFRA-BLOCKED** |
| Claude SMR | in-conversation, `claude-smr-plan-r1.md` | — | written (REVISE→3 folds) |

Notes:
- Two earlier AGY jobs (`adversarial-review-mro41cof-dibj2k`,
  `adversarial-review-mro41uw3-mk3852`) were cancelled — the local
  `origin/master` ref is stale (`dea5ff5`), so `--base origin/master` fed AGY 8
  unrelated commits of noise. Re-dispatched with `--base HEAD~1` for a clean
  plan-only diff.
- **AGY is infra-blocked in this headless environment.** Three substantive
  attempts failed to produce a usable review:
  - `mro438va` — succeeded (exit 0) but produced an off-topic `--print-timeout`
    tangent, never reviewed the plan.
  - `mro46wdv` — no output; auto-denied a `command` permission despite
    `--dangerously-skip-permissions`.
  - `mro47h4p` — no output; same permission auto-deny even with `--no-sandbox
    --dangerously-skip-permissions`.
  Per the standing rule (symmetric to the Codex-infra-blocked exception in
  `feedback_codex_infra_must_retry` / research SKILL.md), the research proceeds
  **2-of-3 (Claude SMR + Codex)** with the AGY failures documented here. AGY
  alone was never the basis for any verdict.

## Round 2 (plan v2 @ e8aaa5e1be5f; SMR r2 folds → v3 @ 845c4b22c8ac)

| Reviewer | Mechanism | Task/Job ID | Status |
|---|---|---|---|
| Codex | codex-companion task --background (re-review) | `task-mro4rkhe-wxi69k` | running |
| AGY | — | — | INFRA-BLOCKED (see r1 notes) |
| Claude SMR | `claude-smr-plan-r2.md` | — | PLAN-READY-WITH-NITS → folded into v3 |

## Round 3 (plan v4 @ 24ba06dfd4fd → v6 @ d74f86994faa)

| Reviewer | Mechanism | Task/Job ID | Verdict |
|---|---|---|---|
| Codex | codex-companion task (re-review) | `task-mro4rkhe-wxi69k` (r2) | REVISE (producer model + Phase-2 safety) → folded into v4 |
| Codex | codex-companion task (re-review) | `task-mro5ghdv-un8fpt` (r3) | REVISE (narrow Phase-1 scoping) — accepted phased convergence → folded into v6 |
| Claude SMR | `claude-smr-plan-r3.md` | — | PLAN-READY (Phase 1 + Phase-2-contract) + 1 nit → folded into v5 |

## Round 4 (plan v6 @ d74f86994faa)

| Reviewer | Mechanism | Task/Job ID | Verdict |
|---|---|---|---|
| Codex | codex-companion task (confirm convergence) | pending | — |
| Claude SMR | `claude-smr-plan-r4.md` | — | pending |
