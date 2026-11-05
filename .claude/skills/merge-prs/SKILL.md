---
name: merge-prs
description: INVALID — do not use. PR merging is prohibited (user directive 2026-11-05); work lands by direct commit. See the campaign skill Step 4.
user_invocable: false
---

# INVALID — superseded by direct-commit landing (2026-11-05)

Do NOT use this skill. Never run `gh pr merge`, never create merge
commits, and do not open pull requests for campaign work.

Current rule (`.claude/skills/campaign/SKILL.md`, Step 4 + standing
orders): lanes push `fix/<issue>-<slug>` branches off current
`origin/master`; reviewers post evidence to the issue; the parent
cherry-picks the branch's commits onto `master` in order, pushes,
closes the issue citing the landed SHA(s), and deletes the branch.
An experimental PR that already exists is closed without landing.

This file is retained only so stale references fail loudly instead
of silently resolving to the old merge procedure.
