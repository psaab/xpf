# `docs/pr/` — PR-scoped review and measurement records

Each subdirectory holds plans, reviews, measurement evidence, and
post-mortems for one PR or closely-related PR series. Contents are
durable artifacts of the adversarial review cycle — NOT working
specs (those live at the repo root `docs/` level).

## Subdirectories

| Dir                          | Scope                                                        | Status                |
|------------------------------|--------------------------------------------------------------|-----------------------|
| `678-hotpath-cuts/`          | #678 poll_binding + pending-forward TX hot-path cuts         | closed (PR #743/#744) |
| `708-enqueue-pacing/`        | #708 enqueue-side pacing on CoS queues                       | closed (PR #734/#742) |
| `709-owner-hotspot/`         | #709 low-rate exact queue owner worker hotspot               | closed                |
| `712-cpu-pinning/`           | #712 operator-facing CPU pinning + IRQ isolation recipe      | closed                |
| `785-umbrella/`              | #785 umbrella — perf fairness plan + cross-worker retrospective | multi-PR (see below) |
| `785-phase3/`                | MQFQ virtual-finish-time scheduler (PR #796)                 | merged `f37597ec`     |
| `797-d3/`                    | mlx5 RSS indirection + knob (PR #797)                        | merged `50acc495`     |
| `800-workers-queues/`        | Workers vs RSS queue-count experiment                        | closed, no PR         |
| `803-tunables/`              | Step-0 zero-code tunables (governor/budget/coalescence; PR #803) | merged `019c3db6` |
| `804-instrumentation/`       | Per-binding ring-pressure counters (PR #804)                 | merged `3d2d63a4`     |
| `807-refactor/`              | Docs refactor into this dir structure (PR #807)              | merged `61ff77c5`     |
| `1316-lowrate-cos-buffers/`  | #1312/#1316 low-rate exact CoS buffer sizing measurements    | PR #1316              |
| `line-rate-investigation/`   | Parent investigation (#798) plan + phase-B step 0 + gaps doc + 8-matrix findings | #798 open |

## Conventions

- Plans live as `plan.md`.
- Reviewer docs: `codex-review.md`, `rust-review.md`, `go-review.md`,
  `systems-plan-review.md` — one per reviewer angle. Append
  `## Round N verification` sections in place; don't fork new files.
- Measurement evidence: `validation.md` (narrative) + `evidence/`
  directory for captured JSON.
- Post-investigation gap analysis: `remaining-gaps.md` (see
  `line-rate-investigation/`).

## When to add a subdirectory

- The work opens a PR that warrants multi-round adversarial review.
- The work is an investigation that may or may not become a PR.
- The work generates measurement artifacts that the author needs to
  cite back from the PR body or from a follow-up issue.

## When NOT to

- Single-commit cleanups or doc typo fixes.
- Feature design docs that live alongside the feature — those stay
  at `docs/` root (e.g. `docs/cos-traffic-shaping.md`).
- Operator-facing references (runbooks, CLI references) — root.

## Convention note (2026-04-21)

Numbered issue/PR plans that previously lived at the `docs/`
root as `docs/<N>-<name>.md` have been migrated under
`docs/pr/<N>-<name>/` with the original filename as a subfile
(plan.md, recipe.md, etc.). This keeps ALL issue-scoped artifacts
discoverable from one index. Non-issue-scoped docs (architecture,
operator guides, feature designs) stay at the root.
