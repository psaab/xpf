# Research-only hostile plan review

Use for requested substantial solution plans, after investigating the problem.
Keep the established Codex + AGY + Claude subject-matter-review (SMR) gate. This
is plan review, not implementation review; the declared-pool triple later reviews actual code
through `/engineer`. Do not open a draft PR just to obtain a fourth plan verdict.

Finding/conclusion validation has its own
[three-way adversarial gate](adversarial-review.md). The same reviewers may handle
both stages with separate verdicts and evidence/plan revisions. File already
validated defects under research's default before waiting for plan convergence;
a missing plan reviewer or PLAN-KILL cannot hold those issues back. Automatic
defect filing does not authorize publishing planning branches or issue comments.

## Prepare the plan

For issue-linked plans, use `research/<issue>-<slug>` and
`docs/research/<issue>-<slug>/plan.md` in an owned documentation worktree under
`<run-dir>/worktrees/<issue>-research-<slug>`, where `<run-dir>` is this run's
`/var/tmp/deep-review-work/research-work.<unique-id>` directory. Base it on the
pinned intended comparison revision. Follow `AGENTS.md`; verify path, base SHA
and write scope. Never reuse
an occupied worktree by force. Without an issue, use the research run ID instead
of inventing an issue number. Local-only plans may stay in the owned run directory.
Commit/push the research docs and post issue comments only within actual scope;
otherwise retain drafts and local evidence. No production source changes.

Preserve these eleven plan concerns, adapted to the actual change. Explain
non-applicable concerns instead of inventing signatures, tests, or measurements:

1. Status and revision: `DRAFT v1`, source/comparison SHAs, current review round.
2. Problem framing: established behavior, evidence, unresolved premises, and
   finding dispositions separate from the proposed solution.
3. Honest scope/value: absolute consequences and costs; distinguish estimates
   from measurements. For performance work, PLAN-KILL is acceptable if the
   supported gain does not justify churn; a real correctness defect still stands.
4. Already shipped work and dependencies: existing behavior to compose with,
   incomplete fixes, delivery limits and relevant prior rejected approaches.
5. Concrete design: proposed types, interfaces, layout and ordering where
   relevant, plus explicit Multiple Path Options and tradeoffs when viable.
6. Public/API compatibility: preserved signatures, wire/config meanings and
   operational behavior; name any proposed change that needs user approval.
7. Hidden invariants: side-effect ordering, ownership/lifetimes, allocation,
   HA portability, stale-state/handle hazards, and cross-consumer guarantees.
8. Risk: behavioral, lifetime/concurrency, performance and architectural-fit
   risks with concrete bounding factors, not just LOW/MED/HIGH labels.
9. Validation: tests that actually exercise the changed contract with independent
   observations, failure cases, acceptance criteria and required environment.
   Use current applicable repository procedures, not historical fixed test counts;
   a proposed live check is not permission to run it during research.
10. Explicit exclusions and deferred work with consequences and owners/next steps.
11. Specific questions for adversarial review, including what would invalidate
    the design. Do not manufacture five questions for a genuinely smaller plan.

## Review, revise, and stop

- Dispatch Codex and AGY independently against the exact plan revision and
  evidence. Obtain the Claude SMR pass as a separate hostile assessment, not a
  summary of their conclusions. Preserve domain expertise plus CPU architecture/
  design and software-design scrutiny from the research entrypoint. Recheck an
  immediate rubber stamp for omitted numerical, concurrency or design reasoning;
  do not invent objections merely to make a review look hostile.
- Discover available tools; do not copy obsolete companion paths, model defaults
  or another checkout from historical examples. Record task ID, role/host,
  evidenced model/source, scope and plan SHA in `reviewer-ids.md`. Save each
  round as `codex-plan-r<N>.md`, `agy-plan-r<N>.md`, and
  `claude-smr-plan-r<N>.md` only for the corresponding actual reviewer. A GPT
  coordinator must not call its own pass Claude; a substitute needs explicit
  approval, honest attribution and a distinct filename. Missing tools or empty
  output are missing reviews, not approval.
- Reviewers return PLAN-READY / PLAN-NEEDS-MINOR / PLAN-NEEDS-MAJOR / PLAN-KILL
  with evidence. Revise on substantive dissent, bump the plan revision, and
  re-review changed reasoning. Read actual results; keyword matches or process
  success are not verdicts. Preserve dissent rather than forcing agreement on
  an unsupported premise. PLAN-READY requires all three on the final revision,
  with minor findings resolved; a substantive change invalidates affected passes.
  PLAN-KILLED likewise requires all three to converge on rejecting the final
  reviewed approach. One reviewer's PLAN-KILL is substantive dissent to
  investigate/revise, not an aggregate terminal verdict. If evidence or an
  unavailable reviewer prevents resolution, report the explicit blocker instead.
- Retry a genuine Codex infrastructure failure using fresh tasks, recording the
  failure pattern. After three consecutive matching infrastructure failures,
  stop BLOCKED and request direction; do not silently proceed on fewer reviewers.
  Use spaced runtime-supported waits with user updates, not tight polling. A
  running review is not an infrastructure failure. Other missing reviewers also
  remain an explicit gap unless the user authorizes an exception; never fabricate
  their verdicts. Do not evade tool access or safety restrictions to obtain a pass.
- Keep driving owned reviewer tasks to actual results or a genuine blocker.
  Do not exit a subagent expecting an unsupported Monitor callback to resume it.
  Use the available completion mechanism and retain task IDs for recovery.

The issue and published research-branch docs remain the canonical planning
surface when publication is authorized. Post per-round status and a final comment
with the actual reviewers' verdicts (verbatim except disclosed harness-tag/secret
redaction), plan revision/link, recommended option and why, and unresolved work.
Otherwise include those comments as drafts in the local research result.

STOP at PLAN-READY, PLAN-KILLED, or BLOCKED; do not implement, open a PR, deploy, or
merge. PLAN-READY ends with: "Awaiting manual approval — type `/engineer <issue>`
to proceed to implementation; the declared-pool triple joins on the implementation PR." With no
issue, request an explicit implementation instruction instead of creating one.

PLAN-KILL rejects this proposed approach, not the existence of the problem.
Preserve every finding's independent disposition. Never automatically close a
defect issue because a fix was rejected. If authorized issue management separately
justifies closing a conclusive rejected-proposal issue, use `plan-kill` only with
closure; use `needs-work` for open iteration. Record the evidence and actual issue
state, or the closure/label recommendation if not authorized.

## Delegation contract

Include in each research subagent brief:

> This is research-only. Investigate evidence and preserve contrary evidence and
> unresolved questions. Do not implement, edit production source, open a PR, or
> mutate GitHub outside the explicitly assigned scope. Keep finding validity
> separate from plan approval. Retain actual model/task identities and drive
> owned tasks to results or a genuine blocker; do not return merely because a
> reviewer is still running. Return the research evidence, disposition ledger,
> and, when assigned planning, the plan revision and actual reviewer verdicts.
> Implementation requires the user's later manual approval.
