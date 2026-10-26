---
name: review-pr
description: Drive a hostile network-expert triple-review on a GitHub PR using only the declared model pool (Muse Wonder, Opus 5.5, Codex-6 Astra, GLM-5.3, Kimi K3.1 Pro) — Claude hostile in-conversation plus two parent-dispatched pool reviewers hostile in the background. All three reviewers hostile-verify rather than confirm. Iterate across force-pushes until all reviewers agree. Never autonomously merge — synthesis only.
user_invocable: true
---

# Review-PR Skill

Drive a hostile network-expert triple-review of an existing
GitHub PR using only the declared model pool: **Claude reviews
hostile directly in the conversation, and two more declared-pool
reviewers (any of Codex-6 Astra, GLM-5.3, Kimi K3.1 Pro,
Muse Wonder, Opus 5.5) run hostile in the background. All three
reviewers operate from the presumption that something is wrong
and go hunting — none of them are the "synthesizer-by-default."
Synthesize all three into a single comment on the PR. Iterate
across force-pushes until all reviewers converge. Never
autonomously merge — the merge decision is always the author's.
Copilot is not part of any review gate (user directive 2026-10-26);
do not request, wait for, or evaluate it.**

This skill encodes lessons from the #1256 / #1258 / #1259 / #1260
review sessions: adversarial reviewers occasionally hallucinate
"showstopper" bugs that don't exist in the code (e.g. claimed a
"fatal nameref bug" where the variable was actually defined one
line above the call site); Codex catches sharp mechanical issues
that Claude's first pass misses (e.g. RSS_STEERING free-form
fallback in PR #1260 round-1). Self-correct your own verdict
when another reviewer catches something real.

## Arguments

`/review-pr <pr-number>` — e.g.

```
/review-pr 1260
```

The PR number identifies the GitHub PR to review. The skill
will fetch the current HEAD and the diff, then dispatch two
declared-pool reviewers in parallel while you write Claude's
review in-conversation.

## Standing rules (apply at every iteration)

- **Never autonomously merge.** The user has not asked you to
  merge; report findings and stop. The merge decision is
  always the author's. State this explicitly in every synthesis.
- **All three reviewers count.** Three distinct models from the
  declared pool. If any of them flags a real issue, it's a block
  candidate — even if the other two say MERGE-READY.
- **Network-expert framing.** Prime both dispatched reviewers with HPC
  networking / OS / data structures / JIT / CPU design /
  networking protocols expertise. The codebase is xpf, an
  eBPF-based firewall with userspace AF_XDP dataplane in Rust.
- **Verify reviewer claims against the actual code.** If a
  reviewer claims a variable is undefined or a function
  doesn't compile, GREP / READ the file at that exact commit
  before propagating the claim. Reviewers have hallucinated
  showstopper bugs in this codebase before (#1260 round-2
  "fatal nameref bug").
- **Self-correct your own verdict.** If a pool reviewer catches
  a real issue you missed, post a correction in the synthesis.
  Don't double down. "I missed this" preserves trust.
- **Iterate across force-pushes.** If the author force-pushes a
  new commit during the review, restart the cycle on the new
  commit. Note both the old and new SHAs in the synthesis.
- **Stay in cache window.** Use `ScheduleWakeup` with
  `delaySeconds=240-270` (under the 5-minute cache TTL) when
  waiting for pool reviews; bigger delays burn the
  prompt cache.
- **Hostile means hostile — all three reviewers.** Claude and both
  dispatched pool reviewers all operate from the
  presumption that something is wrong. For both dispatched reviewers,
  write the prompt so reviewers feel licensed to push back —
  phrase every check as "verify hostile" with a bullet list
  of failure modes. For Claude (Step 3), enter the review
  expecting to find something. A first-pass MERGE-READY is a
  yellow flag: ask what numerical / concurrency / edge case
  you skipped before posting it.

## Step 0: Inspect the PR

```bash
# Always fetch latest before reading
git fetch origin pull/<PR>/head:pr-<PR>-head -f
git fetch origin master
gh pr view <PR> --json headRefOid,headRefName,state,mergeable,title,additions,deletions,files

# Optional: prior reviewer state
gh api repos/psaab/xpf/pulls/<PR>/reviews
gh api repos/psaab/xpf/pulls/<PR>/comments
```

**Always rebase the review worktree onto current master before reviewing**, so the review reflects the mergeable state (catches drift, conflicts, and build breakage that aren't visible in the PR diff alone):

```bash
# In an isolated worktree dedicated to this review:
WT=/var/tmp/worktrees/pr-<PR>-review
git worktree add -B pr-<PR>-review-rebased "$WT" pr-<PR>-head
cd "$WT"
git rebase origin/master
# Resolve conflicts if any — if conflicts are non-trivial, that itself is a review finding.
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build --release 2>&1 | tail -5
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go build ./... 2>&1 | tail -5
```

If the rebase fails with conflicts: that's a real finding. Document it in the synthesis and either (a) resolve mechanically and continue review on the post-rebase tree, or (b) flag the conflict as a merge blocker that the author must resolve. Don't silently review only the PR diff.

If the post-rebase build/tests fail but the pre-rebase build was clean: that's a master-drift regression. Flag it in the synthesis as a blocker — the PR is not in a mergeable state until rebased.

Record:
- Current HEAD SHA (this is what reviewers will see)
- Branch name
- File-level diff stat (additions/deletions per file)
- State (OPEN / MERGED)
- Any prior review iteration on this PR
- **Rebase result**: clean fast-forward / clean rebase / conflicts (list them) / build breakage post-rebase
- **Post-rebase SHA** (note it in the synthesis if different from the PR head)

If MERGED, this is a post-merge review (e.g. retrospective
follow-up scope assessment). Frame the synthesis as
"NEEDS-FOLLOWUP / CLEAN" rather than "MERGE-READY".

## Step 1: Read the diff

Use `git show <SHA>` or `git diff <base>..<SHA>` to read the
full diff. Don't just rely on the PR body — the author's
summary may understate or overstate scope.

Quantify:
- Total LOC delta
- Files touched (and their layer: dataplane / control / docs / tests)
- Cross-cutting concerns (HA sync, GC, kernel state, BPF
  verifier-sensitive code)
- Hot-path vs slow-path classification

If the diff is large (>500 LOC), section it: focus first on
public API changes, then on data-structure changes, then on
control flow.

## Step 2: Dispatch two declared-pool reviewers in parallel

Dispatch two background reviewers via the internal `task` tool,
each requesting a DISTINCT model from the declared pool (Muse
Wonder, Opus 5.5, Codex-6 Astra, GLM-5.3, Kimi K3.1 Pro) other
than the in-conversation Claude model. NEVER external CLI model
tools (codex/agy/claude CLIs). Reviewers are READ-ONLY,
worktree-scoped at the PR head, and end with exactly one verdict
line: MERGE-READY / MERGE-NEEDS-MINOR / MERGE-NEEDS-MAJOR.

Brief template (fill per PR):

```
You are a hostile network-expert reviewer (HPC networking / OS /
data structures / CPU / networking protocols; xpf is an eBPF
firewall with a userspace AF_XDP Rust dataplane). Review PR #<PR>
at head <SHA> in <worktree>. Presume something is wrong. Verify
every claim against the code at this SHA and cite file:line;
reproduce findings where possible. Prior reviewers on this
codebase have hallucinated showstopper bugs that don't exist
("fatal nameref bug" where the variable was defined one line
above the call site) — verify before claiming MAJOR.

Diff stat: <FILE> (+ADD/-DEL).
Round-<N> context: <prior verdicts + findings; omit on round 1>.

Verify (be hostile — fail the commit if any finding is real):
A. <Specific check tied to file:line>
B. <Specific check tied to file:line>
...

Verdict: MERGE-READY / MERGE-NEEDS-MINOR / MERGE-NEEDS-MAJOR.
```

Record both task IDs. After dispatching both, also dispatch
Claude's review as a background agent (Step 3), then wait for
convergence. Reviewers typically take minutes, not seconds; do
not poll output-mtime as liveness.

## Step 3: Dispatch Claude's review as a background agent — HOSTILE

The Claude review runs in a dedicated **background agent**, not in
the main conversation. This keeps the main thread free for the
user, lets Claude's review run in parallel with both pool reviewers,
and avoids dumping reviewer-prose into the conversation context.

Dispatch via the `Agent` tool with `subagent_type: "general-purpose"`
and `run_in_background: true`. The agent's job is to read the diff,
write the hostile review, post it to the PR via `gh pr comment <PR>`,
and return only a short "review posted at <URL>" summary.

### Completion notification — act on the task-notification, don't wait for the poll

When a background agent finishes, the harness emits a
`<task-notification>` message to the dispatcher (this conversation).
**Treat that notification as the trigger to advance the synthesis** —
read the agent's posted PR comment, fetch any pool reviewer
results that have also landed, and post the per-PR synthesis
immediately. Don't wait for the next `ScheduleWakeup` cycle if the
notification fires first.

If multiple `<task-notification>` events arrive close together
(common when 3 PRs in flight), batch the work — post each PR's
synthesis as its reviewers converge, even if other PRs still have
pending reviewers. Don't hold a ready synthesis hostage to an
unrelated PR's pending state.

The dispatched agent's prompt should reinforce this by saying:
"Post the review and return only the comment URL — do not summarize
the findings to me; the parent task will read the PR comment
directly."

Example Agent dispatch:

```
Agent({
  subagent_type: "general-purpose",
  description: "Claude hostile review of #<PR>",
  run_in_background: true,
  prompt: "You are the Claude hostile reviewer in a three-reviewer declared-pool methodology (Claude in-conversation plus two dispatched pool reviewers) on PR #<PR> commit <SHA>.

  Repo: /var/tmp/worktrees/pr-<PR>-review

  Read the full PR diff and write a hostile review. Post the review as a single PR comment via `gh pr comment <PR> --body \"...\"` and return only the comment URL.

  <SKILL_STEP_3_HOSTILE_GUIDANCE_VERBATIM>

  Verdict format and post template are in Step 3 of the review-pr skill. Do not merge. Do not dispatch reviewers yourself; those are already dispatched by the parent."
})
```

The `<SKILL_STEP_3_HOSTILE_GUIDANCE_VERBATIM>` block below must be
passed inline to the agent so it has the full hostile-posture +
required-checks + network-expert framing context.

**Be hostile.** Claude is the in-conversation hostile reviewer in this
methodology — not the synthesizer-by-default. Across this
codebase's history, Codex has caught mechanical issues Claude
missed (RSS_STEERING fallback in #1260, leading-zero collision
in #1260, numerical-stability cancellation in #1261). That
pattern is a failure mode: Claude defaulting to "MERGE-READY,
math checks out" while a sharper reviewer demonstrates a real
bug. Counteract it by entering each review with a presumption
that something is wrong and going hunting.

### Hostile posture

- **Presume something is wrong.** Read the diff with the
  expectation that you'll find an issue. If your first pass
  says MERGE-READY, ask: what numerical / concurrency / edge-
  case did I skip past? What untested code path exists?
- **Hostile-verify the author's claims.** PR body says "no
  per-packet allocation" — search for any allocation in the
  hot path. PR body says "tests pass" — run them. PR body
  says "matches X reference" — do the math by hand.
- **Reproduce findings**, don't just describe them. If you
  spot a potential bug, write a worked example or run a test
  proving it; if you spot a potential numerical issue, do the
  Taylor expansion or ULP analysis.
- **No softening hedges** ("might be a concern", "would be
  nice if"). State findings directly with severity and a
  reproduction path. If you can't reproduce, say so.
- **Score yourself afterward.** When the pool reviewers come back
  with a real finding you missed, explicitly post a self-
  correction and revise your verdict. Don't double down.
  Track the miss pattern.

### Required hostile checks for every PR

For each item below, the question is not "does this look OK?"
but "what could go wrong here, and how do I prove it?"

- **Diff coverage hostile check**: did the author touch ONLY
  what they claimed? `git diff --stat <base>..<head>` — flag
  any file outside the PR body's list.
- **API stability hostile check**: did any public signature
  change? `grep` for callers of changed signatures across the
  full codebase, not just the PR's diff. Are tests for the
  callers also updated?
- **Data-structure invariants**: alignment, padding, BPF map
  serialization (cilium/ebpf uses native endian for `__be32`,
  never `BigEndian`), lifetime/borrow shape, slab/handle
  invariants. Hostile angle: what happens if the struct is
  reordered? What if a field is added in the middle?
- **Hot-path allocation rules**: per-packet allocations are
  forbidden; per-CPU scratch maps for cross-stage data. Grep
  for `make(` / `Vec::new` / `Box::new` in any function reached
  from the packet path or coordinator tick.
- **Concurrency**: lock ordering, ArcSwap vs separate atomic
  fields (single ArcSwap is preferable for atomic publish),
  acquire/release pairing. Hostile angle: write down the
  reader/writer interleaving that could observe inconsistent
  state.
- **Numerical correctness**: does the code use
  catastrophic-cancellation patterns like `E[X²] − E[X]²`? Do
  the math by hand for an extreme input (very large, very
  small, near-uniform, severely skewed). Check that the
  asserted test values match an independent computation, not
  just what the implementation produces.
- **Backward compatibility**: does this break existing
  callers or smoke tests? Grep for deprecated patterns and
  ensure either migration or hard-reject.
- **Test coverage**: do the tests exercise the actual call
  sites, or just the helper functions in isolation? A test
  that exercises `helper_fn()` directly will pass even if the
  call-site code regresses to a buggy form.
- **Smoke matrix coverage**: did the author run the full
  matrix (v4+v6, push+reverse, CoS-off+CoS-on, all 7 classes)?
  If they only ran a subset, ask why.
- **Edge cases the author didn't list**: empty input,
  single-element input, all-identical input, overflow/underflow,
  truncation, integer wraparound, FP denormal/NaN/Inf, what
  happens when the channel is full / closed / the goroutine
  panics. Pick ones the author didn't explicitly test.

### Network-expert framing

Apply these specifically for network-dataplane PRs:

- Byte order on packet fields — `binary.NativeEndian` for BPF
  `__be32`, never `BigEndian`.
- BPF verifier — branch merges lose packet range, stack limit
  512 bytes across call frames, `__u16` causes sign-extension.
- XDP/SR-IOV — iavf is generic-mode only, redirect_capable
  fallback, XDP on PF doesn't see VF traffic.
- AF_XDP/UMEM — fill ring, completion ring, single-owner
  binding, fairness regime (multinomial floor).
- Checksum arithmetic — one's-complement wrap, u32 accumulator
  bounds, SIMD-vs-scalar parity for chained checksums.
- VRRP / HA — RETH virtual MAC, fabric forwarding, sync
  protocol, writeMu serialization.

### Claude background agent posts the review

The Claude background agent is instructed to post its review
itself via `gh pr comment`. Template the agent should use:

```bash
gh pr comment <PR> --body "$(cat <<'EOF'
## Claude round-<N> review on `<SHA>`

**Verdict: MERGE-READY / MERGE-NEEDS-MINOR / MERGE-NEEDS-MAJOR**

<Verdict summary>

### Findings

<Each finding with file:line citation>

### Verification

<Specific things you grep'd / read to confirm>

### Recommendation

<Block / strongly consider / defer>

Awaiting pool reviewers (`task-<ID>`, `task-<ID>`).
EOF
)"
```

## Step 4: Wait for both pool reviewers, then verify

When `ScheduleWakeup` fires:

Collect both pool reviewers' task results when they complete
(they auto-deliver; use `wait` only when genuinely blocked).

For each reviewer finding:

1. **Cross-check against the actual code**. If the reviewer
   cites `file:line`, read that line. Confirm the claim.
2. **Distinguish real-bug from scope-expansion.** Adversarial
   pool reviewers
   often demand hardware-grade isolation, NIC Flow Director
   rules, IRQ affinity coordination, etc. — these may be
   legitimate but beyond the PR's stated scope. Mark them
   "defer to follow-up" rather than "block".
3. **Catch hallucinations.** Past third-party reviewers have claimed:
   - "Fatal nameref bug" where variable was defined one line up
   - "Build would fail to compile" where build succeeded in 28s
   - Stale replay of a prior commit's finding
   The pattern repeats across reviewers; verify every
   finding against the actual code before propagating.
4. **Note self-corrections.** If a pool reviewer catches a
   real issue Claude missed, revise Claude's verdict in the
   synthesis. Don't double down.

## Step 5: Synthesize and post

The synthesis is a SHORT consolidation step — verdict matrix +
per-finding cross-check + recommendation. Keep it in the main
conversation by default (it produces one short PR comment and
self-correction notes that the user wants to see in real time).

If the user has multiple PRs in flight at once and explicitly
asks to "do everything in background", also delegate the
synthesis to a background agent — pass the agent the 4 reviewer
outputs (Claude PR comment URL and both pool result texts) and have it cross-check
each finding against actual source and post the synthesis
comment itself, returning only the comment URL.

Post a single consolidated comment with the matrix:

```bash
gh pr comment <PR> --body "$(cat <<'EOF'
## Round-<N> triple-review consolidated synthesis on `<SHA>`

| Reviewer | Verdict |
|---|---|
| Claude | <verdict> |
| Pool reviewer 1 | <verdict> |
| Pool reviewer 2 | <verdict> |

### <Reviewer> finding — <severity>

<Verbatim or paraphrased> at `file:line`.

**Cross-check**: <what I read / grep'd to verify>

**My read**: <real bug / scope expansion / stale / false>

[Repeat for each finding from each reviewer]

### <Hallucination/stale finding> — VERIFIED FALSE

<Reviewer> claimed <X>. Verified by reading <file:line>:
\`\`\`
<actual code>
\`\`\`
<X> is incorrect.

### Recommendation

**Block on:** <real findings>
**Strongly consider in this PR:** <minor>
**Defer to follow-up:** <scope expansion>

Pool tasks: `<id>`, `<id>`. Not merging.
EOF
)"
```

## Step 6: Watch for the next iteration

If the author responds with a force-push or new commit:

1. Detect: re-run `gh pr view --json headRefOid` and compare.
2. If SHA changed: restart the cycle from Step 0 with the new
   SHA. Note in the next synthesis that this is round-N+1.
3. Read the diff between old and new SHA to see what the
   author fixed.
4. Re-dispatch reviewers with **round-N context**: tell them
   what the prior round flagged and what the author claims to
   have fixed. Hostile-verify the claims.

If the author merges or closes the PR while you're mid-review:

- Stop the cycle.
- Post a final summary if the synthesis from the latest round
  has not been posted yet.

If the user explicitly tells you to stop, stop. Don't keep
polling.

## Lessons encoded from prior sessions

### Codex catches mechanical bugs Claude misses

- PR #1256 round-3: Codex caught `SHAPER_RATE_BPS` shared
  across mixed evals (canonical 1G + 10G classes both got the
  default 25G shaper). Claude missed this.
- PR #1260 round-1: Codex caught the `RSS_STEERING` free-form
  fallback in `network_domain()` accepting two arbitrary
  strings as proof of network isolation. Claude missed this.
- PR #1260 round-2: Codex caught the leading-zero suffix
  collision (`_01` overwrites `_1`). Claude saw it as minor
  footgun; Codex demonstrated the silent overwrite.
- PR #1260 round-3: Codex caught the bash arithmetic
  wraparound at 2^64 (`_18446744073709551616` collides with
  `_0`). Claude verified the regex but missed the integer
  overflow class.
- PR #1261 round-1: Codex caught the closed-form variance
  cancellation at billion-scale inputs (`[1e9, 1e9+1]`
  collapses to 0). Claude verified the math against the Rust
  reference at small-flow scale but didn't probe the
  catastrophic-cancellation edge.

That is **five misses on four consecutive PRs**. Treat it as
a hard pattern: when reviewing, hunt for the mechanical /
numeric / edge case that Codex would flag, before posting
MERGE-READY. Enter the review with the presumption that
something is broken.

Self-correction: when Codex catches something real, revise
Claude's verdict in the synthesis. Don't double down.

### Third-party reviewer hallucinations — verify before propagating

(Historical pattern from prior reviewers; the same discipline
applies to every pool model — different model, same failure mode.)

- PR #1260 round-2: third-party reviewer claimed "fatal nameref bug"
  where `cmd_name` was undefined. Verified false — `cmd_name` was
  defined one line above the call site.
- PR #1256 round-3: third-party reviewer claimed the SIMD/scalar
  checksum agreement test "passed in debug mode only because you forced
  both scalar and SIMD to agree on the wrong mathematical answer". The
  math was correct for realistic packet sizes (production max ~2 GB
  sum, far below 2^32 wrap).

When any pool reviewer raises a MAJOR claim, grep the cited line FIRST.
If the claim doesn't hold, mark it VERIFIED FALSE in the synthesis
and let the sharpest pool reviewer be the deciding voice.

### Reviewers replay stale findings

- PR #1256 round-3 + round-4: a reviewer's inline at
  `fairness-eval.rs:cstruct-max` was replayed from `e6e7c71d`
  even though `f07db4b8` had already fixed it.
- Cross-check every replayed finding against the CURRENT
  commit, not just trust the comment.

### Adversarial reviewer widens scope

- PR #1256 / #1260 round-1+: prior third-party reviewer consistently
  demanded hardware-grade isolation (Flow Director rules, IRQ
  affinity, remote `/proc/self/status` probe) on PRs whose stated
  scope is opt-in hostile-qualification, not enforced hardware
  isolation. These are legitimate concerns for a future
  hardware-grade mode but not blockers for the current PR.
- Expect adversarial reviewers to do the same. Mark scope-expansion findings
  "defer to follow-up" rather than "block".

### Self-correction in synthesis preserves trust

When you wrote MERGE-READY initially and a pool reviewer catches
a real issue, post a self-correction:

> "Self-correction: My round-N Claude review flagged X as
> 'minor footgun, not blocking'. A pool reviewer demonstrated the
> silent overwrite is real — I should have called this
> fix-before-merge. Revising my verdict to MERGE-NEEDS-MINOR."

This pattern preserves trust over time. Don't double down on
a wrong verdict.

## Quick reference — internal dispatch only

Reviewers run ONLY via the internal `task` tool with declared-pool
models. NEVER external CLI model tools (codex/agy/claude CLIs).

```bash
# PR data
gh pr view <PR> --json headRefOid,headRefName,state,mergeable
gh pr comment <PR> --body "..."
gh api repos/psaab/xpf/pulls/<PR>/reviews
gh api repos/psaab/xpf/pulls/<PR>/comments

# PR fetch
git fetch origin pull/<PR>/head:pr-<PR>-head -f
git diff <base>..<head>
git show <SHA> -- path/to/file
```
