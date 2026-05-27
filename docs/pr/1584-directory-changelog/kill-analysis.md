# #1584 plan v1 — PLAN-KILL analysis

Both Codex and AGY were dispatched hostile plan-review of v1
(commit 5ab2ec15) at 2026-05-27 03:17 UTC.

## Verdicts

- **AGY** (review-mpnhx7m5-s7qu58, completed 03:21 UTC): **PLAN-KILL**
- **Codex** (task-mpnhwj7v-lbe4tu, completed 03:26 UTC): **PLAN-NEEDS-MAJOR**

While Codex's verdict is technically not a KILL, the substantive
findings overlap 7/9 with AGY's KILL points, and the cumulative
weight is sufficient to conclude this plan iteration is dead. A v2
would need to reframe enough that it's effectively a new plan.

## Overlapping findings (both reviewers)

### F1 — Migration heuristic misroutes actual entries (Codex #1, AGY #1)

Current `_Log.md` is **issue-number-keyed**, not PR-number-keyed:

- Line 28: `## 2026-05-26 23:43 UTC — #1348 icmp_embed split (PR #1596...)`
  — first `#N` is the issue #1348, but the routing target should be
  PR #1596.
- Line 261: `## 2026-05-26 — #1326 PR #1569 AWAITING-BATCH-MERGE...`
  — first `#N` is issue #1326, but the PR is #1569.

The plan's first-`#N` routing heuristic produces `_Log/PR-1348.md`
and `_Log/PR-1326.md`, both wrong if the convention is GitHub PR
numbers. Either the convention should be issue-based, or the
migration needs an issue→PR lookup table.

### F2 — PR numbers don't exist during local development (Codex #2, AGY #4)

The plan says `<N>` is "the closing PR number". But GitHub allocates
PR numbers at `gh pr create` time, AFTER local commits land. Log
entries are written DURING development.

This forces one of three bad outcomes:

1. Premature draft-PR creation just to claim a number (CI spam,
   blocks offline work).
2. Stale placeholder filename (e.g. `PR-XXXX.md`) renamed after PR
   open (force-push churn).
3. Issue-number-based naming instead, which is what the existing
   `_Log.md` headings actually use.

The plan does not address this. Option 3 is the cleanest fix and
also resolves F1.

### F3 — `merge-prs/SKILL.md` hardcoded `_Log.md` resolver breaks (Codex #8, AGY #6)

Verified at `.claude/skills/merge-prs/SKILL.md:61-63`:

```bash
# Check for _Log.md conflicts only
if git diff --name-only --diff-filter=U 2>/dev/null | grep -q '_Log.md'; then
  git checkout --theirs _Log.md && git add _Log.md && git commit --no-edit 2>/dev/null
fi
```

This is the automated conflict-resolver the smoke-runner relies on
to land batches without manual intervention. Under the new layout
it silently does nothing (the unmerged path is `_Log/PR-N.md`, not
`_Log.md`). The skill MUST be updated in the same PR.

### F4 — `MISC-YYYY-MM-DD.md` reintroduces the conflict (Codex #5, AGY #7)

33 of 87 existing top-level sections have no `#N` in the heading.
Some are date-only headers (cross-cutting session journals). Two
parallel sessions on the same date both append to
`_Log/MISC-2026-MM-DD.md` and collide on tail-append.

Mitigation: use `SESSION-<UTC>-<slug>.md` or similar uniqueness key,
not date-only.

### F5 — Freeze-footer edit is itself a final conflict hazard (Codex #7, AGY #8)

The migration PR itself appends to `_Log.md` (the freeze footer).
Every active in-flight branch with `_Log.md` deltas will conflict
on that footer when rebased onto master. The "queue depth ≤ 3"
mitigation doesn't cover dormant or offline branches.

Codex also flagged a subtle second bug: the proposed footer text
references "this PR's own merge commit", which is unknowable from
inside the PR itself.

### F6 — In-flight rebase coordination is unrealistic (Codex #6, AGY #3)

The plan asks ~30 in-flight branch owners to run
`scripts/rebase_log_to_dir.sh` and force-push. Codex did a worktree
audit and found 73 worktrees with `_Log.md` deltas (some stale).
Hand-wavy.

AGY's superior alternative: **transitional dual-read / dual-write
grace period.** Tooling reads from BOTH `_Log.md` and `_Log/*.md`.
Old branches continue to append to `_Log.md`; new branches use
`_Log/PR-<N>.md`. Eventually `_Log.md` is frozen as historical when
all live branches have drained naturally. No coordinated force-push.

### F7 — Renderer cannot be both losslessly-reconstructing and chronological-by-file (Codex #3)

The plan says the renderer sorts files by first timestamp; the plan
also says reconstruction-diff verifies losslessness against the
original `_Log.md`. But the current `_Log.md` is not monotonic
(line 3719 = 2026-05-13, line 4312 = 2026-05-26). PR files like
#1476 and #1529 span multiple days.

File-level first-timestamp sort cannot reconstruct the original
order. Either render must sort by manifest/original order for
verification, or by per-`##`-section parsing for the chronological
view — but not file-level first-timestamp for both.

## AGY-only findings

### A1 — `*.md` glob non-recursive (AGY #5, #10)

AGY claims the `*.md` glob in the carry-forward rule at
`feedback_smoke_serialized_single_agent.md:62` would NOT match
`_Log/PR-1584.md` because `*.md` is non-recursive.

**Partial truth.** In bash, `*.md` is non-recursive. But the
carry-forward rule's actual usage is `git diff --name-only` (which
returns nested paths verbatim, no glob) + an English description
("only `*.md` / `_Log.md` / docs"). The English description should
be updated, but the underlying git command is not affected. Codex
correctly judged this finding as mostly-okay (Codex #8: "is mostly
okay because `_Log/PR-*.md` is still `*.md`").

### A2 — Long-term directory bloat (AGY #9)

5000+ files in `_Log/` over years. AGY suggests partitioning
(`_Log/2026/PR-*.md`). Valid concern; cheap to add in v2.

## Codex-only findings

### C1 — Renderer ordering contradiction (Codex #3 — captured as F7 above)

### C2 — Skill/memory audit incomplete (Codex #8)

Plan said "skills under `.claude/skills/` may grep `_Log.md`. Audit
each in the implementation step." Should have been done IN THE PLAN,
not deferred. The merge-prs hit (F3) is the load-bearing one.

## Net assessment

The plan has 7 substantive structural issues that overlap across
both reviewers, plus 3 additional reviewer-specific findings, plus
the explicit AGY KILL verdict citing "the cure is worse than the
disease." Iterating v1 → v2 → v3 to address all of these would be
effectively a new plan rather than a revision; the right call is
to mark v1 KILLED and either:

1. Drop the issue (rely on existing carry-forward fast-path), or
2. Open a fresh issue / plan with the revisit-criteria from the
   plan's Status section, particularly the issue-number naming +
   dual-read-write transition.

Decision deferred to issue owner. This sub-agent stops here.

## Reviewer transcripts (verbatim)

### Codex task-mpnhwj7v-lbe4tu

> **Verdict: PLAN-NEEDS-MAJOR**
>
> Directory-based logging is the right direction; I would not
> PLAN-KILL the architecture. But this plan is not ready. It
> overclaims "PR-number" uniqueness while the current workflow and
> migration data are issue-number shaped, and the renderer/losslessness
> story is internally inconsistent.

[9 findings, abbreviated above]

### AGY review-mpnhx7m5-s7qu58

> **Verdict: PLAN-KILL**
>
> While PR #1584 aims to solve the genuine pain of tail-append
> merge conflicts in `_Log.md`, the proposed directory-based
> architecture introduces several severe structural flaws,
> circular dependencies, and automated tooling breakages that are
> significantly worse than the conflict friction it attempts to
> resolve.

[10 findings, abbreviated above]
