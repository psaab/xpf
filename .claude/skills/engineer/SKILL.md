---
name: engineer
description: Alias for /triple-review — drive a refactor through the full triple-review methodology (three declared-pool reviewers: Muse Wonder, Opus 5.5, Codex-6 Astra, GLM-5.3, Kimi K3.1 Pro) with plan-review, smoke, and 3-of-3 merge gate.
user_invocable: true
---

# /engineer — alias for /triple-review

`/engineer <issue-number> <one-line scope>` is identical to
`/triple-review <issue-number> <one-line scope>`. Both invocations
run the same triple-review methodology codified in
`.claude/skills/triple-review/SKILL.md`.

When invoked, immediately invoke the `triple-review` skill via
the Skill tool, forwarding the arguments verbatim:

```
Skill({skill: "triple-review", args: "<verbatim args>"})
```

Do not duplicate the methodology here. The single source of
truth is `.claude/skills/triple-review/SKILL.md` — any change
to the methodology (e.g. the plan-review gate at Step 3, the code-review gate at Step 8,
the marker-post protocol, the smoke-runner handoff)
applies to `/engineer` automatically because this skill is a
thin forwarder.
