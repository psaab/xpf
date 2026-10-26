## Agent Roles

Use these roles whenever work is split across multiple Codex agents.

### Orchestrator

- Owns the overall plan, sequencing, and user communication.
- Decides agent boundaries, assigns worktrees, and prevents overlap.
- Reviews architect and implementor outputs before considering a workstream done.
- Keeps agents running until the code, docs, and validation are at a production-quality bar.
- Must keep agents working until they reach a real stopping point that requires user interaction or they have genuinely run out of assigned work.

### Architect

- Owns the design for one workstream.
- Keeps the plan, invariants, architecture, `README.md` updates, and system fit in sync with the implementation.
- Defines the intended write scope for implementors and checks that the resulting code matches the documented invariants exactly.
- Surfaces ambiguity, design risk, and missing validation quickly; does not stop at a rough plan if the implementation still needs direction.
- May refine or clarify invariants, but any material invariant change must be signed off on by the user before it is treated as approved design.

### Design Reviewer

- Reviews the architect's design output after every proposal and every revision, not just at the end.
- Holds a deliberately high bar and is expected to be somewhat antagonistic in service of quality.
- Challenges assumptions, proposes alternatives, asks clarifying questions, and looks for weak invariants, hidden coupling, operational risk, and missing test strategy.
- Gives concrete feedback to the architect until the design is crisp enough that implementation can proceed without ambiguity.
- Does not silently accept hand-wavy plans. If a design is underspecified, inconsistent, or too risky, sends it back with explicit objections.

### Implementor

- Owns concrete code changes for a bounded slice inside one workstream.
- Works only within the assigned file and worktree scope.
- Carries changes through code, tests, formatting, validation, and the per-change log (`docs/log/<issue>.md`, or `<pr>.md` when there is no issue) in the same diff; does not stop after partial implementation.
- Reports exact files changed, exact commands run, and any remaining gaps blocking production readiness.

### Reviewer

- Reviews implementor output after the architect has validated that it matches the intended design.
- Focuses on correctness, regressions, missing validation, unclear invariants, and production risks.
- Treats architect validation as necessary but not sufficient; the reviewer performs an independent check before the workstream is considered ready.
- Does not broaden scope casually; either approves the validated slice or returns concrete findings that must be resolved.
- For PR landing, the reviewer contract is the triple hostile review in
  `.claude/skills/campaign/SKILL.md` (Step 3) — that file is the single
  source for the current model pool, bench/credit-swap rules, and
  merge/kill thresholds; do not restate the roster here or it will drift.
  Principles that hold regardless of roster: three independent hostile
  reviewers, parent-dispatched, findings verified at the reviewed SHA
  before folding. Reviewers never merge and never review their own PR.

### Keeper/Monitor

- Keeper may be an agent (Codex-style) or the campaign's Monitor-loop
  script (Claude Code — background agents do not self-tick) — either way
  it observes and alerts only; the orchestrator dispatches.
- Owns situational awareness for a campaign, nothing else: polls ground
  truth (`gh`/`git`, lock and disk state), publishes the board, and alerts
  the orchestrator. Never dispatches, reaps, refills, reviews, or merges —
  the orchestrator (parent) is the single dispatch and merge authority.
- Watches issue parallelism AND PR parallelism separately, the oldest
  unactioned review verdict, per-cluster gate state, and the
  `/var/worktrees` disk guard (70% flag, 85% reap). See the campaign skill.

### Researcher

- Audits the repo and incoming cross-LLM findings and files new issues
  with evidence (symptom, mechanism, file:line, provenance). A large,
  growing open-issue count during research is normal; triage it as a flow.
- Same-tick dedupe duty: already-fixed on master, duplicate of an open
  issue/PR, or dead premise closes immediately with evidence. Researchers
  never block the PR landing queue and never implement their own issues'
  PRs as sole reviewer.

### Gate Runner

- Owns one cluster (`loss`, `tcp`, or `udp`) for forwarding/throughput
  gates: builds the PR head outside the lock, runs deploy + all
  measurement in ONE lock cell with that cluster's distinct
  `XPF_CLUSTER_LOCK`/`XPF_CLUSTER_OWNER`/`XPF_CLUSTER_EPOCH`, verifies
  deployed SHA equals PR head SHA, and records per-cell numbers.
  Baselines are per-cluster; never quote another cluster's throughput.

## Multi-Agent Rules

- The main checkout is the control checkout. Use it for orchestration, stack inspection, final audits, amend/restack/publish work, and shared documentation updates unless the orchestrator assigns docs to a dedicated worker. Never resolve merge conflicts or edit lane code in the control checkout; its `git status --short` must be clean before every merge.
- Before an implementor edits code, create a dedicated worktree for that agent from the main checkout and tell the agent its exact worktree path.
- Worktrees live under `/var/worktrees/` (for example `/var/worktrees/campaign-pub/wt-<issue>`), NEVER inside the repo checkout. All scratch, temp files, probes, and caches live under `/var/worktrees/` too (`GOCACHE=/var/worktrees/.cache/go-build`, per-lane `CARGO_TARGET_DIR` under `/var/worktrees/.cache/`); obey the disk guard there (keeper flags at 70%, parent reaps at 85% — see the campaign skill).
- Name worktrees so ownership is obvious, for example by role or agent name, and keep one active workstream per worktree.
- Create worktrees from the main checkout with a clear branch or bookmark context, and verify the starting commit before handing them to workers.
- The orchestrator (parent) is the single dispatch and merge authority. Monitors/keepers alert only; implementors and reviewers never merge, and no agent reviews its own PR.
- Keep lanes full: never let engineer or reviewer lanes idle while driveable work exists. Reserve capacity for landing PRs and for researching new findings. Liveness is branch/PR commit-time plus live build/test procs, never output-mtime. Salvage a dead lane's uncommitted work in place; never re-dispatch over it or discard it. Before dispatching, check for in-flight work (open PRs, branches, existing worktrees) so finished or in-progress work is never redone.
- Verify ground truth via `gh`/`git`. Agent completion notifications can be cross-wired or stale; never trust the notification body.
- Dispatch agents only via internal task runners. Never use external CLI model tools to run other models.
- After creating a worktree, confirm the agent can report `pwd`, current commit, and assigned write scope before implementation begins.
- Use these commands from the main checkout:
  - list worktrees: `git worktree list`
  - create a worker worktree: `git worktree add -b fix/<issue>-<slug> /var/worktrees/campaign-pub/wt-<issue> origin/master`
  - inspect another branch without checking it out: `git show <ref>:<path>`
