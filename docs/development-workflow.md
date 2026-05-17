# Development workflow — plan, review, code, review, merge

> Deprecation notice (#1373): new dataplane work and routine forwarding
> validation target the Rust AF_XDP userspace dataplane by default. The legacy
> eBPF dataplane remains in-tree for compatibility, rollback, and explicit
> regression coverage during the staged retirement. Phase 1 updates active
> documentation; later phases own source, loader, build, and CLI removals.

How non-trivial changes land in this repo. Roles and agent-boundary
rules are in `AGENTS.md`; read that first. This doc is the process
layer on top of those roles.

The workflow has two distinct review cycles — one on the plan, one
on the code — each with the same rule: **land when both reviewers
agree, not before**.

```
               ┌──────────────────────────────────────────────┐
               │                                              │
  PLAN PHASE   │  Architect drafts plan                       │
               │         │                                    │
               │         ▼                                    │
               │  Design Reviewer  ←───╮  hostile / pedantic  │
               │  (Codex)              │  adversarial by      │
               │         │             │  default (AGENTS.md  │
               │         ▼             │  §Design Reviewer)   │
               │  Findings → Architect │                      │
               │         │             │                      │
               │         └─────────────╯                      │
               │                                              │
               │  Loop until BOTH agree PLAN-READY YES        │
               └──────────────────────────────────────────────┘
                                  │
                                  ▼
               ┌──────────────────────────────────────────────┐
               │                                              │
  CODE PHASE   │  Implementor writes code per the plan        │
               │         │                                    │
               │         ▼                                    │
               │  Reviewer (one or more) ←─╮  Codex + second  │
               │                           │  reviewer (Rust, │
               │         │                 │  Go, systems —   │
               │         ▼                 │  pick the angle) │
               │  Findings → Implementor   │                  │
               │         │                 │                  │
               │         └─────────────────╯                  │
               │                                              │
               │  Loop until BOTH agree MERGE YES             │
               │                                              │
               │         ▼                                    │
               │  Merge PR                                    │
               └──────────────────────────────────────────────┘
```

## When this workflow applies

- Non-trivial code changes in `userspace-dp/`, `pkg/daemon/`,
  `pkg/dataplane/`, or any hot path.
- Any PR that claims a performance improvement.
- Any PR that could regress fairness (CoV), throughput, retransmits,
  or latency on measured matrices.
- Any PR that introduces a new configuration knob or an externally-
  observable behavior change.

When it does NOT apply:
- Single-commit doc typo fixes.
- Pure test-only additions that don't change production code.
- Dependency bumps with no behavior change.

## Phase 1 — Plan review cycle

### Architect step

The architect (an agent or human) drafts a plan doc at
`docs/pr/<issue-or-pr>/plan.md`. The plan must contain:

- **Problem statement** — what's wrong, measured with citations.
- **Hypotheses** — enumerated, each with an associated diagnostic.
- **Thresholds and statistics** — every number has either a
  derivation (math or simulation) or a named source (a prior
  measurement file).
- **Execution matrix** — what gets measured / built, in what order,
  with budgets.
- **Validation gates** — what must pass between steps, specifically.
- **Rollback** — what breaks, how to detect, what to revert.
- **Non-negotiables** — invariants that must not drift.
- **Hard stops** — the exact conditions that HALT execution.
- **Deferrals** — findings acknowledged but explicitly not handled
  in this plan, with rationale.

### Design Reviewer step (Codex, adversarial)

Per `AGENTS.md` §Design Reviewer, Codex is invoked with a hostile
disposition. The reviewer:

- Reads the plan and every document it references.
- Flags each concern with **severity (HIGH / MEDIUM / LOW)**, a
  **file:line citation**, and a **concrete mitigation**.
- Does not silently accept hand-waving. Hand-wavy math or unjustified
  thresholds are MEDIUM or HIGH findings.
- Writes the review to `docs/pr/<issue-or-pr>/<plan-name>-review.md`.

The Design Reviewer's output is **binding**. The plan is NOT ready
while any HIGH or MEDIUM is open.

### Architect response

The architect addresses every HIGH and MEDIUM. Each is either:

- **Fixed** — cite the specific section / line that now addresses
  it. Attach math, code, or a commit SHA.
- **Explicitly deferred** — written rationale + risk statement.
  Silently dropping a finding is NOT acceptable.

LOW findings: fix if cheap, else defer with a one-liner.

### Loop

Each Design Reviewer round appends a
`## Round N verification` section to the review doc:

- CLOSED / PARTIAL / STILL OPEN per prior finding.
- New findings introduced by the fix.

The loop terminates when the reviewer writes at the TOP of the new
section: **"ROUND N: PLAN-READY YES"**.

Typical round count: 2-4. Observed on this repo: up to 7 rounds on
complex measurement plans. That's fine — every round catches
something real.

## Phase 2 — Code review cycle

### Implementor step

The implementor follows AGENTS.md §Implementor rules. Writes code
on a dedicated branch, in scope, with tests. The plan doc is the
spec. No scope creep without going back to the Architect.

Commit style per the repo (one commit per coherent step, `<area>: #N
— <short>`, `Co-Authored-By:` trailer, signed-off-by).

### PR submission

Open a PR. Body includes:

- Link to the plan.
- Summary of what changed.
- Test plan with checkboxes for each invariant.
- Before/after measurements where applicable (statistical gate per
  the plan's rollback protocol).

### Reviewer step (two angles, in parallel)

**Codex, adversarial** (same personality as Design Reviewer):

- Reads the PR, the plan, and every code file changed.
- Flags HIGH / MEDIUM / LOW with citations and mitigations.
- Writes `docs/pr/<N>/codex-review.md` (or `codex-review-roundN.md`
  per round).

**Second reviewer, different angle** (spawn in parallel):

- Rust quality, Go quality, test coverage, or systems/OS, depending
  on the PR's content.
- Writes `docs/pr/<N>/<angle>-review.md`.

Both reviewers produce independent findings. They must NOT duplicate
angles — if Codex is covering correctness, the second reviewer
covers testability or idioms.

### Implementor response

Same rules as plan revision: every HIGH / MEDIUM fixed or deferred
with rationale. LOW fixed if cheap.

### Loop

Each code review round produces a `## Round N verification` append
to each reviewer's doc. Terminates when BOTH reviewers write
**"ROUND N: MERGE YES"** at the top.

Typical round count: 2-3. Observed up to 4.

## Merge rules

- PR is merged ONLY after BOTH code reviewers sign off with MERGE
  YES in the latest round.
- Merge commit subject: `Merge pull request #N from <branch>`.
- Post-merge: update master locally, delete the branch (leave
  historical artifacts in the `docs/pr/<N>/` directory intact).
- If the PR is part of a stacked series, merge bottom-up.

## Test target is the userspace cluster, never bpfrx

Line-rate, fairness, CoS, and forwarding validation targets ONLY
the **`loss:xpf-userspace-fw0` / `loss:xpf-userspace-fw1`** cluster.
The `bpfrx-fw0` / `bpfrx-fw1` eBPF-dataplane cluster is **not** a
supported measurement surface for these workstreams — its setup,
config schema, and deploy pipeline are orthogonal.

If an agent captures evidence from `bpfrx-*` VMs, the evidence is
invalid. Regenerate on the userspace cluster and update the
referencing doc. This applies to VDSO captures, strace outputs,
kernel/glibc fingerprints, iperf3 runs, and any counter snapshot.

## Forwarding health is a continuous gate

At any point during either cycle — plan execution OR code
implementation — forwarding must stay healthy on the test cluster.
Specifically (on the userspace cluster):

- `iperf3 -c 172.16.80.200 -P 4 -t 5 -p 5203` passes with 0
  retransmits after any daemon restart.
- The 12-flow baseline (`iperf3 -P 12 -t 20 -p 5203`) does not
  regress past the plan's rollback threshold.
- Under CoS: the 8-matrix doesn't regress on the forward-shaped
  cells.

If any check fails mid-cycle: STOP, rollback the offending commit,
investigate, report. Do not continue with a broken cluster.

## Documentation conventions

- Plans and reviews live in `docs/pr/<issue-or-pr>/`.
- Numbered plan: `plan.md` (or `recipe.md` for operator-facing
  runbooks; pick one, stick to it).
- Reviews: `<reviewer-angle>-review.md` — one file per reviewer,
  appended on each round (not new file per round).
- Validation evidence: `validation.md` narrative + `evidence/`
  for raw captures (JSON iperf3, counter snapshots, etc.).
- Feature/architecture docs stay at `docs/` root.
- See `docs/pr/README.md` for the full index.

## Why this workflow

- Bugs caught at the plan stage cost orders of magnitude less than
  bugs caught in code review, which cost orders of magnitude less
  than bugs caught in prod.
- Two independent reviewers with different angles surface
  different bug classes. One-reviewer PRs ship bugs the other
  would have caught.
- Adversarial-by-default Design Reviewer prevents the "looks
  plausible, LGTM" failure mode. Examples from this repo where
  hostile review caught real bugs:
  - Phase 3 MQFQ: HIGH vtime-not-restored-on-push_front (would
    have silently broken fairness under TX-ring pressure).
  - Phase 4 cross-worker throttle: BLOCKER coalescence-gated-off
    (would have regressed the win we'd just measured).
  - Step 1 plan: 3 rounds of HIGH findings on statistical
    threshold derivation before execution started.
- Writing "ROUND N: PLAN-READY YES" is a commitment, not a
  formality. Reviewers who sign off on something that later breaks
  in prod own the breakage.

## Summary

1. Architect writes a plan.
2. Adversarial reviewer (Codex) tears it apart.
3. Architect revises. Loop until both agree PLAN-READY YES.
4. Implementor codes per the plan.
5. Two reviewers (Codex + second angle) independently find issues.
6. Implementor revises. Loop until both agree MERGE YES.
7. Merge.

Forwarding stays healthy throughout. Documentation lives in
`docs/pr/<N>/`. Every finding is either fixed or explicitly
deferred — silently dropping findings is not acceptable at any
stage.
