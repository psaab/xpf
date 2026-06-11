# Reviewer task IDs — #1864 research

## Round 1 (plan r1, commit 42aab8fbc)

| Reviewer | Task ID | Verdict |
|---|---|---|
| Codex | task-mq9bc63m-80h5m3 (session 019eb613-826a-71e1-8702-d211e8c73bed) | PLAN-NEEDS-REVISION (8 findings) |
| AGY | adversarial-review-mq9axojw-2uci47 | PLAN-NEEDS-REVISION (6 findings) |
| Claude SMR | docs/research/1864-toolchain-pin/claude-smr-plan-r1.md | PLAN-READY w/ F1+F2 revisions |

## Round 2 (plan r2 3541536c9 / r2.1 3333a8f4d)

| Reviewer | Task ID | Verdict |
|---|---|---|
| Codex | task-mq9cyqzu-n1bmwp (session 019eb63d-3220-7cf0-9c10-4ae1999c193c) | PLAN-NEEDS-REVISION (all 8 r1 closed; 5 new: 1 HIGH C1-spec-validation wording, 4 MED/LOW) |
| AGY | adversarial-review-mq9bmafk-47842g | PLAN-NEEDS-REVISION (minor: F7 taskset, F8 toml parse, F9 git-diff gate; all r1 closed; single-PR approved) |
| Claude SMR | docs/research/1864-toolchain-pin/claude-smr-plan-r2.md | PLAN-READY |

## Round 3 (plan r4) — convergence round

Codex r2 finding 1 (HIGH) was a plan-wording gap only: the implementation
shares verifyUserspaceShimSpecOnly (incl. validateUserspaceShimSpec) between
C1 and C2 from the first commit. Findings 2-5 implemented:
shrink-equivalence root-gated test + preserved REJECT testdata, derived
worker-core mask with nice-only fail-safe, broadened ordering invariant,
strict single-channel TOML parse. Plan r4 records all five.
