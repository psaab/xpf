---
name: campaign
description: Drive ALL open issues to terminal (MERGED / PLAN-KILLED / PLAN-DEFERRED-with-reason) — a drive-to-zero campaign. Ranks the backlog, fans out /research + /engineer agents (parallel route) or chains coupled work (serial route), PARENT-reviews every PR, files new issues found during audits, and stops when nothing driveable remains.
user_invocable: true
---

# /campaign — drive-to-zero backlog campaign

Drive **every** open issue to a terminal state — `MERGED`,
`PLAN-KILLED`, or `PLAN-DEFERRED-needs-lab-or-operator-with-reason-recorded-on-the-issue`
— and open new issues for real bugs/gaps found along the way, then drive
those too. Stop only when no driveable work remains.

This skill is the orchestration layer ABOVE `/research` and `/engineer`.
It does not re-implement them — it ranks the backlog, picks a route
(parallel or serial), fans out agents, and enforces the merge discipline.

## Arguments

```
/campaign                       # autonomous: rank the whole backlog, drive it to zero
/campaign <n> <n> ...           # drive a specific set of issues
/campaign serial <n> <n> ...    # force the serial route for a coupled set
/campaign parallel <n> <n> ...  # force the parallel route for a disjoint set
```

No args = full autonomous drive-to-zero over every open issue. With a
cron tick (CronCreate), each firing re-enters this skill and advances the
campaign; `CronDelete` when the backlog is terminal.

## The cardinal rule

**You (the PARENT) own review and merge.** The companion lane (Codex/AGY)
is infra-degraded and SERIAL (one Codex + one AGY globally), and spawned
engineer agents CANNOT dispatch their own sub-reviewers. Therefore:

- **PARENT dispatches an independent hostile Claude reviewer for EVERY
  PR** (a `general-purpose` agent, read-only, worktree-scoped, ends with a
  verdict). See `/review-pr` for the hostile-review shape.
- **PARENT reads + EVALUATES Copilot inline on the FINAL head BEFORE
  every merge** — grep each cited line, decide real/stale, fold real
  findings. Printing Copilot is not evaluating it. (This rule exists
  because #2285 shipped a HIGH re-entrant deadlock that was
  printed-not-evaluated.)
- **PARENT merges**, never the spawned agent. Agents implement + test +
  open the PR and STOP.

## Step 0: Reconcile ground truth (every tick)

```bash
git -C /home/ps/git/bpfrx fetch origin master
git -C /home/ps/git/bpfrx rev-parse --short origin/master
gh issue list --state open --limit 100 --json number,title,labels,body \
  --jq '.[] | "#\(.number) [\(.labels|map(.name)|join(","))] \(.title[0:60]) | \(.body|length)c"' | sort -n
gh pr list --state open --json number,title,headRefName,mergeable \
  --jq '.[] | "\(.number) [\(.mergeable)] \(.headRefName)"'
```

Then `TaskList` to read the tracking task (the campaign's state-of-record),
and wedge-check any running agents. **Liveness = branch/PR commit-time AND
active cargo/go procs — NOT agent output-mtime** (a 5x-flake-check looks
idle but isn't; don't premature-kill). Do NOT read agent JSONL transcripts
(they overflow context); use the completion notification or a bounded
`grep -ao` of the `.output` file to recover a dropped verdict.

## Step 1: Rank the backlog

Sort every open issue into priority bands, highest first:

1. **Correctness / security bugs** (data-plane drops, fail-open, UAF,
   deadlock, wrong-tuple classification, no-transit).
2. **Features** with a clear spec.
3. **Refactors** (pure code-motion preferred — no architectural premise to
   fail).
4. **Lab/operator-bound** — needs hardware, a live capture, an operator
   secret/URL, or a maintainer decision.

Within each band, prefer issues whose IMPLEMENTATION is driveable now even
if final verification is lab-bound — **ship the code, defer only the
lab-verify** (record the deferral on the issue).

Classify each issue as **disjoint** (touches files no other in-flight issue
touches → parallel route) or **coupled** (shares files / depends on another
issue's merge → serial route). Record the ranking + route on the tracking
task.

### `plan-deferred` is NOT a terminal state — it is a WORK QUEUE

**A `plan-deferred-*` label parks nothing. Drive-to-zero means every open
issue reaches MERGED or a rigorously reviewed PLAN-KILL — not a `plan-deferred`
label that leaves the issue open forever.** Deferring with a reason is a
throughput failure, not a disposition. The correct response to a hard problem
is to `/research` it to a converged plan and `/engineer` it to a merge (or a
2-of-3-reviewed KILL), NOT to write "defer, revisit on demand" and move on.

So on every campaign pass, **re-open the `plan-deferred` set and drive it**:

- **`plan-deferred-research`** (design/refactor/needs-a-plan) → this is the
  MAIN queue. `/research` each to a converged plan, then `/engineer` it to a
  MERGE. A refactor whose premise is stale (file already under threshold, target
  already extracted, already-fixed) → CLOSE it as such (that IS terminal). A
  refactor that survives review as genuinely-not-worth-it → PLAN-KILL with the
  2-of-3 verdict (label `plan-kill`, close). "Unproven codegen risk" is a reason
  to add an asm-diff gate and DO the extraction, not to defer it indefinitely.
- **`plan-deferred-operator` / `plan-deferred-lab`** → **ship the CODE, defer
  only the external verify.** A "needs an operator decision" is a design
  question to resolve in `/research` (pick the safe default, document it) then
  implement; a "needs hardware/a live capture" ships the implementation +
  records the specific lab-verify as the only outstanding item on the issue.
  Do NOT let "operator/lab" block the code.
- The ONLY genuinely-terminal-without-driving case is a maintainer-held issue
  you were explicitly told not to touch → record the hold reason, leave open,
  do NOT touch held code.

Never write a fresh `plan-deferred` label to escape a hard item. If `/research`
converges on PLAN-KILL, that is terminal (label `plan-kill`, close). If it
converges PLAN-READY, `/engineer` it to a merge. There is no third "deferred"
outcome except a maintainer hold or a hard external dependency whose CODE is
already shipped.

## Step 2: Pick a route

### Parallel route (default — disjoint issues)

Fan out wide. For each disjoint issue, dispatch a `general-purpose`
engineer agent (or `/research` first if the design needs human judgement).
Run as many concurrently as the box allows.

- **Unique `CARGO_TARGET_DIR=/dev/shm/cargo-<issue>` per Rust agent** — 8
  concurrent `cargo --release` against one target dir thundering-herds and
  starves them all. Cap concurrency to ~cores.
- Each agent: fresh worktree off CURRENT master
  (`git worktree add -b fix/<n>-<slug> .claude/worktrees/<n> origin/master`),
  implement + fail-on-revert tests + build green + open PR ("Closes #<n>")
  + STOP (do not merge, do not dispatch reviewers).
- **Commit-message standard (lanes, enforced)** — state verbatim in every dispatch/fold brief; parent bounces non-conforming branches before review (`git log` shape check at PR intake).
  - Subject: `<area>: <imperative summary> (#NNNN)`, ≤72 cols. Area vocabulary: `docs:`, `test:`, `assurance:`, `forwarding:`, `config:`, `daemon:`, `cluster:`, `sessions:`, `audit:`, `show:`, `telemetry:`, `nftables:`, `ha:`, `frr:`, `process:`, `userspace-dp:`, `afxdp:`, `policy:`, `nat:`, `firewall:`, `grpcapi:`, `snmp:`, `ipsec:`, `xdp:`, `shim:`, `ci:`, `build:`, `metrics:` (new areas allowed when none fits, never bare). Summary names the BEHAVIOR change in imperative mood (`gate`, `drop`, `reject`, `refund`, `sync`, `bound`, `fence`), not the file (`update foo.rs`). Parent process commits without an issue cite the ruling (`(user-directive 2026-09-22)`).
  - Body (required, via `git commit -F -` heredoc, wrapped ~72 cols) has four sections:
    1. `Why:` the defect mechanism + consequence — what breaks, who/what is affected, under what config/traffic. 2–5 lines. Cite the path (`poll → session → TX`), not just "fixes bug".
    2. `What:` approach + key files/symbols + deliberate scope cuts (`NOT changed: X because Y`). A reader must know where to look without opening the diff.
    3. `Validation:` exact commands + results — new tests with RED evidence (`fails pre-fix with <assertion>`), suites with totals (`6980 passed, 1 failed (#9894, base-attributed on <sha>)`), BPF verifier headroom for shim changes, lint state.
    4. `Risk:` residuals, follow-ups filed (`#NNNNN`), operator-visible behavior deltas. Omit only when genuinely none — never omit silently on enforcement-path changes.
  - One logical change per commit; each commit builds; squash WIP/scratch before push. Split fix vs test-only vs docs vs generated-artifact regen vs review-fold into separate commits. Review-fold commits describe what review finding they address and why, never `address review`.
  - PROHIBITED: `Issue #NNNN:` prefix form, ref-less subjects (`Fold review hardening`), title-only commits, `wip`/`fix`/`misc` checkpoint messages on pushed branches, backticks in `git commit -m` (heredoc always — messages contain backticked identifiers).
  - Good: `userspace-dp: refund ICMP budget on policy refusal (#10667)` + Why (refused errors exhaust the 64-burst, starving permitted ones) / What (carry budget_key through reversal arms; refund at TTL/CoS/policy terminals) / Validation (3 cells RED pre-fix; full --bins 6952+1 #9894@<sha>) / Risk (post-queue TX drops still unrefunded — rare, pre-existing).
  - Bad: `fix icmp bug`, `Issue #10667: update embedded_icmp.rs`, `Fold review hardening` (no ref, no behavior, no validation).
- **Worktree hygiene is absolute**: agents point at `.claude/worktrees/<x>`,
  NEVER the main checkout. Read other branches via `git show <ref>:<path>`,
  never `git checkout` in the main checkout.

**Batch-smoke optimization (disjoint dataplane PRs):** integrate N
disjoint dataplane PRs onto ONE integration branch and run ONE loss-cluster
iperf smoke to validate them all, then merge them individually. Code in
disjoint regions auto-merges; only `_Log.md` needs a union and a shared
file touched by two PRs needs an additive merge (keep both — e.g. gre.rs
`outer_ecn_bits` ‖ `inner_dst_ip`). This amortizes the shared cluster lock.

### Serial route (coupled issues)

When issues share files or one depends on another's merge, chain them: each
agent bases off the PRIOR merge, not stale master. Use this for:

- A multi-increment refactor (each commit/PR builds on the last).
- Issues that touch the same hot file (avoid N-way `_Log`/code conflicts).
- A feature whose pieces have an ordering dependency.

Drive one to MERGED, fetch master, then start the next off the new master.
Slower but conflict-free; the right call when the parallel route would just
manufacture merge conflicts.

## Step 3: Review every PR (PARENT)

For each PR an agent opens:

1. **Re-verify the FINAL head** — `gh pr view <n> --json headRefOid`.
   Authors iterate then go quiet; heads MOVE (a review-fold lands after you
   started). Always review/merge the current head, not the one you saw.
2. **Dispatch an independent hostile Claude reviewer** (background
   `general-purpose`, worktree-scoped, read-only, verdict-first). Bar by
   risk:
   - pure code-motion → reviewer + SMR + tests
   - hot-path / failover / session / CoS / HA / RA / FRR / WG →
     full review + loss-cluster smoke (`test-failover` for failover,
     iperf for dataplane)
   - upgrade / correctness / security → thorough review
3. **Read + evaluate Copilot inline on the final head** as a SEPARATE step
   before merge. Fold real findings.
4. **Fold review findings** by resuming the engineer agent
   (`SendMessage({to: "<agentId>", ...})` — resumes a COMPLETED agent with
   its context intact) OR inline if the agent's worktree is at a stale
   pre-rebase head that would overwrite your rebase.

Copilot routinely catches substantive incompleteness the hostile reviewer
passes (e.g. a fail-closed bound by slice length instead of the
IP-declared length; a cmsg underflow). Both gates must clear.

## Step 4: Merge (PARENT)

Per PR, in order:

1. Re-poll `mergeable` THROUGH `UNKNOWN` (GitHub recomputes after every
   push) until `MERGEABLE`/`CLEAN` or `CONFLICTING`.
2. If `CONFLICTING` (almost always `_Log.md` after master advanced): in a
   FRESH worktree off the PR branch, `git merge origin/master`, **union the
   `_Log.md`** conflict (keep both blocks, drop the markers), build-check if
   a behavior-relevant file conflicted, push the rebased branch via
   `git -C`. NEVER resolve in the main checkout.
3. Set the PR title + body first: `gh pr edit <n> --title "<area>: <summary> (#NNNN)" --body-file /tmp/pr<n>_body.md` (body with Why/What/Validation + gate evidence). Then merge with an explicit pair: `gh pr merge <n> --merge -t "<area>: <summary> (#NNNN)" -F - <<<"<same body>" --delete-branch`. Both flags REQUIRED together: `-t` alone yields a title-only merge whose body echoes the subject, and bare merge yields GitHub's `Merge pull request #N` template — both are log pollution (ruled 2026-09-22). `git fetch origin` first if the ref may be stale, then verify with `git log --format=%B -1 origin/master` after merging.
4. Verify the issue auto-closed (`Closes #<n>` in the body). If not,
   `gh issue close <n>` with a comment citing the merge SHA + smoke result.
5. Fetch master; the NEXT PR now needs its own `_Log` rebase vs the new
   master — repeat.
**Control-cleanliness gate (2026-09-22 incident: 24 lane-leaked files sat in the control tree and silently wedged every `merge --ff-only`, leaving control 15 merges behind):** before EVERY merge-prep, run `git status --short` in control — it MUST show nothing except known `.claude/worktrees/` untracked entries: zero M/A/D/R lines AND zero unexpected `??` lines. If dirty: STOP; `git stash push -m control-rescue-<date>` (tracked only, NEVER `-u`: worktrees live under untracked dirs); confirm with `git stash list` BEFORE resetting; `git fetch origin` then `git reset --hard origin/master`; triage the stash per-file (duplicate-of-branch → drop after lane confirms; unique → rescue to the owning lane); triage unexpected `??` paths individually (`mv` aside per-file for inspection, NEVER `git clean -fd`). NEVER blanket-checkout a dirty control tree and NEVER `merge --ff-only` into one. Restate worktree discipline to all lanes after any incident.

**NEVER backticks in `git commit -m`** — use `git commit -F -` heredoc (PR
bodies + commit messages contain backticked identifiers).

## Step 5: File-new during audits

Keep an adversarial-audit lens running. When a review or audit surfaces a
real bug/gap that's out of the current PR's scope, **file a new issue**
(with RFC/spec basis + a concrete fix + provenance) and drive it in a later
round. The campaign isn't done when the initial backlog is empty — it's
done when the backlog STAYS empty after an audit.

## Step 6: Final cross-PR integration audit

After a wave of PRs lands close together, the per-PR reviews each saw only
their ISOLATED diff. Dispatch ONE bounded audit agent over the COMPOSED
master to catch integration bugs the per-PR reviews structurally cannot:

- shared files touched by ≥2 PRs (distinct counters not arg-swapped after a
  shared fn gained a param; gate ordering — suppression BEFORE
  classification; no aliasing in merged data paths)
- wire/protocol fields added by ≥2 PRs all tag-matched on BOTH Rust+Go
  sides (a one-sided field = #1961-class no-transit risk); regenerate +
  diff `protocol_wire_v1.json`
- composed-master build (cargo + go) + the cross-language contract test

If it finds a real bug → file + drive it (defer termination). If CLEAN →
proceed to Step 7.

## Step 7: Terminate

**Termination requires EVERY open issue to be `MERGED` or `PLAN-KILLED`
(2-of-3-reviewed, labeled `plan-kill`, closed).** A `plan-deferred` label is
NOT a terminal state — see "`plan-deferred` is NOT a terminal state" above. If
any open issue still carries a `plan-deferred-*` label, the campaign is NOT
done: go back and drive it (`/research` → `/engineer` → merge, or `/research`
→ PLAN-KILL). The ONLY exceptions that may remain open at termination are (a) a
maintainer-held issue you were told not to touch, and (b) an issue whose CODE is
already merged and whose ONLY remaining item is a hardware/live-capture verify
you cannot perform — and that must say exactly that on the issue.

When EVERY open issue (including newly-filed) is `MERGED` or `PLAN-KILLED` (per
the above), and the final integration audit is clean:

1. Update the tracking task to COMPLETE with the merged list + deferred set.
2. Write a campaign memory file (`project_campaign<N>_<date>.md`) + a
   one-line `MEMORY.md` index entry capturing the non-obvious lessons.
3. If cron-driven: `CronDelete` the campaign cron.
4. `PushNotification` a one-line outcome (the user may be away).

## Standing rules (apply throughout)

- **Re-verify the FINAL head** before review and before merge — heads move.
- **Liveness = commit-time + active procs**, not output-mtime. Don't
  premature-kill a flake-checking agent. Orphaned test procs from a
  COMPLETED agent ARE safe to kill (zombies, not live work).
- **Cross-wired completion notifications happen** — a task-id from agent A
  can carry a body about agent B's PR, or claim a merged PR is still open.
  VERIFY ground truth via `gh`/`git`, NEVER trust the notification body.
- **Detached smoke** = script-file + no-pipe RC + wait-for-xpfd-solidly-up
  + a `DONE` marker; watch it with `Monitor` (until-grep-marker) or
  `Bash(run_in_background)`. A `cmd | grep; echo $?` returns grep's status
  and can false-pass a failed test.
- **`gofmt -w`** a pre-existing-dirty Go file when your PR touches it.
- **API may 529** — fall back to doing the work inline.
- **Base every PR on CURRENT master** (three-dot diff; a fork-behind
  branch shows false mass-deletions on two-dot — use three-dot to see true
  change + two-dot only as a mass-deletion tripwire).

## Hard-won operational lessons (from live runs)

- **Verify an issue is not ALREADY FIXED before dispatching.** The open list
  carries stale issues whose fixing PR merged but whose auto-close never
  fired (e.g. #5732 was already fixed by #5733). Before writing a dispatch,
  grep the cited symbol on `origin/master`
  (`git show origin/master:<file> | grep <symbol>`) and/or
  `gh pr list --state merged --search "<keyword> in:title"`. If present,
  `gh issue close <n>` citing the fixing PR + pick another. A "residual"
  follow-up issue may have been closed by its OWN later PR — check. Keep the
  agent's STEP-0 as the backstop, but do the parent check too so lanes are
  not spent on no-ops.

- **Salvage a DEAD engineer's uncommitted work — do not clobber it.** An
  engineer can die mid-task leaving substantial uncommitted work in its
  worktree. First CONFIRM death (not silence): unreachable mailbox AND no
  file/gocache writes AND no live build procs for several minutes — a
  recent-but-static mtime + no procs means it stopped, not that it is
  thinking. Then SALVAGE, do not re-dispatch (a re-dispatch to the same
  worktree/branch clobbers the work): parent verifies it (build + full
  `-race` + a firsthand RED-on-revert on the core guard), commits it, opens
  the PR, and runs it through the SAME gate with EXTRA completeness scrutiny
  in the independent review — a dead agent left no one to defend it, and a
  sweep may be 24/25 correct with one missed site (the #5886 salvage: the
  review caught a panic-site in a package the sweep never touched). NEVER
  `git checkout -- <file>` in a dirty salvage worktree — it discards the
  uncommitted work (recover from the diff if you do).

- **Cross-review when the reviewer pool is thin.** engineer≠reviewer does
  NOT require idle spectator agents: the engineer of PR A reviews PR B and
  vice-versa. Freeing idle agents for a "small workflow" is fine — refill
  reviewers by cross-assigning the active engineers, or spawn one fresh
  reviewer once panes free.

- **Copilot is often quota-blocked for a whole window** ("reached their
  quota limit"). That does NOT waive the gate — it makes the Copilot-eval a
  no-op, so the load-bearing gate is the parent firsthand RED-on-revert PLUS
  the independent hostile Claude review. Still read the Copilot review on
  the final head every merge; it is frequently just the quota message.

- **A design fork surfaced mid-`/engineer` → STOP and defer to `/research`.**
  If scoping reveals a real design decision (a data-model change, a
  producer→facility mapping, a backward-compat behavior change, a
  multi-PR-sized "full" option vs a bounded one — e.g. #5797), do NOT pick a
  scope blind. Record the scoping analysis on the issue, label it
  `plan-deferred-research`, and let the plan-review gate + user decide. That
  is a legitimate terminal-without-driving state, not a failure to drive.

## Anti-patterns this skill prevents

- Merging with unevaluated Copilot findings (the #2285 HIGH-deadlock class).
- Building an integration branch on a stale PR head, then merging it and
  silently reverting the author's later review-fold.
- N-way merge conflicts from running coupled issues on the parallel route.
- Declaring "done" when the initial backlog emptied but an audit would
  surface more — keep the audit lens on until it comes back clean.
- Thundering-herd cargo builds (shared target dir) starving each other.
- Trusting agent output-mtime as liveness and killing a live flake-check.

## When NOT to use this skill

- A single isolated fix → `/engineer <n>` directly.
- A design that needs human judgement before any code → `/research <n>`,
  stop at PLAN-READY, let the user approve.
- An incident/outage → fix directly; don't run a backlog sweep.
