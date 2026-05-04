---
name: triple-review
description: Drive a refactor through the full triple-review methodology — plan with Codex + Gemini (round-1 PLAN-KILL is acceptable), implement, smoke-test on loss userspace cluster, PR, wait for Copilot, dispatch Codex + Gemini hostile code review, merge only once all three agree.
user_invocable: true
---

# Triple-Review Refactor Skill

Drive a refactor end-to-end through the project's engineering
practice: **plan with Codex + Gemini in parallel before any code
touches, ship pure code-motion when possible, smoke-test every
batch on the loss userspace cluster, get all three of Codex,
Gemini, and Copilot to agree before merging.**

This skill encodes lessons from #946 Phase 1 (shipped after 3
plan-review rounds, all PLAN-NEEDS-MAJOR), #946 Phase 2
(plan-killed by both Codex and Gemini independently), #964
slab refactor, and earlier Phase 1-11 of #959 BindingWorker
decomposition.

## Arguments

`/triple-review <issue-number> <one-line scope>` — e.g.

```
/triple-review 964 SessionTable slab + integer handles (Step 1 of multi-index refactor)
```

The issue number identifies the GitHub tracking issue. The
one-line scope distinguishes a multi-step refactor's current
increment.

## Standing rules (apply at every step)

- **Plan first, code never first.** Never edit code before the
  plan has cleared at least one round of Codex + Gemini.
- **Both reviewers must agree.** If Codex says PLAN-READY and
  Gemini says PLAN-NEEDS-MAJOR, iterate. If both say PLAN-KILL,
  stop and report — do NOT push through.
- **Smoke v4 AND v6.** Every test cycle hits both
  172.16.80.200 and 2001:559:8585:80::200. v4-only smoke masks
  dual-stack regressions.
- **Smoke push AND reverse.** Every iperf3 invocation runs
  twice: once default (push, client→server) and once with `-R`
  (reverse, server→client). Push-only smoke once let a TX-path
  regression cap reverse at ~2 Gbps while push still hit line
  rate. Multi-stream `-P 12` is the canonical reproducer.
- **Smoke CoS-disabled AND CoS-enabled.** Run the matrix twice:
  once with CoS configuration removed (best-effort only — this
  catches regressions in the unshaped fast path) and once with
  the per-class CoS config applied. CoS-only smoke masks fast-
  path regressions; best-effort-only smoke masks classifier and
  shaper regressions.
- **Per-class CoS smoke for refactor PRs.** Hit ports
  5201-5206 (one per configured CoS class). Combined with
  push+reverse, v4+v6, and CoS-disabled/enabled passes, that's
  4 baseline + 2 multi-stream + 24 per-class = 30 measurements
  per refactor.
- **Never dismiss a failing test.** If any reviewer reports a
  test failed, prove it passes locally (named test 5x + full
  suite + Go suite) BEFORE merging. "Sandbox-only flake"
  handwave is not allowed.
- **Wait for Copilot.** After `gh pr create`, poll until
  Copilot review lands. Address every comment.
- **Refactor: <Pattern>" issues that don't fit the codebase
  reality SHOULD be killed at plan time.** #946 Phase 2,
  #961 PacketContext both died this way. Don't push through
  a wrong-target architecture.

## Step 0: Setup

```bash
# Worktree off origin/master, named after the issue.
ISSUE=$1
SCOPE_SLUG=$(echo "$2" | tr ' ' '-' | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9-')
git -C /home/ps/git/bpfrx fetch origin master
git -C /home/ps/git/bpfrx worktree add \
  -b refactor/${ISSUE}-${SCOPE_SLUG} \
  .claude/worktrees/${ISSUE}-${SCOPE_SLUG} \
  origin/master

# CD into the worktree for everything that follows.
cd /home/ps/git/bpfrx/.claude/worktrees/${ISSUE}-${SCOPE_SLUG}
```

## Step 1: Read the issue + study the affected code

```bash
gh issue view $ISSUE --json title,body
```

Walk the affected code with `Read` and `grep`. Identify:

- The data structures / functions the issue targets.
- All public API methods (count + list them).
- Cross-cutting state (HA sync, GC, iter, shared maps).
- Hot path vs slow path classification.
- Existing batch boundaries (e.g., `scratch_forwards`,
  `scratch_recycle`).

Quantify the blast radius:

```bash
grep -rn "<TARGET>" userspace-dp/src/ --include='*.rs' | wc -l
grep -rn "use.*<TARGET>" userspace-dp/src/ --include='*.rs' | wc -l
```

## Step 2: Draft the plan (single doc, all front-matter inline)

Path: `docs/pr/${ISSUE}-${SCOPE_SLUG}/plan.md`. Required sections:

1. **Status** line — `DRAFT v1 — pending adversarial plan review`
2. **Issue framing** — what the issue asks for, in your words.
3. **Honest scope/value framing** — what the win actually is at
   absolute scale (cycles, MB, retransmits). Always include the
   line: *"If reviewers conclude the perf gain is too small to
   justify the churn, PLAN-KILL is an acceptable verdict."*
4. **What's already shipped / partially batched** — pre-existing
   relevant work that the plan must compose with.
5. **Concrete design** — types, signatures, memory layout, with
   code snippets. Sketch the main-loop transformation if it's a
   pipeline change.
6. **Public API preservation** — list all preserved method
   signatures.
7. **Hidden invariants the change must preserve** — at minimum:
   side-effect ordering, allocation rules, HA sync portability,
   stale-handle hazards, lifetime / borrow-checker shape.
8. **Risk assessment** — 4-class table:
   - Behavioral regression risk (LOW/MED/HIGH)
   - Lifetime / borrow-checker risk
   - Performance regression risk
   - Architectural mismatch risk (#961 / #946-Phase-2 dead-end pattern)
9. **Test plan** — cargo build clean, 952+ cargo tests, 5/5 named
   test flake, 30 Go packages, smoke v4 + v6, per-class CoS
   5201-5206, optional perf measurement.
10. **Out of scope (explicitly)** — list deferred follow-ups.
11. **Open questions for adversarial review** — at least 5
    specific questions, each invitable to PLAN-KILL.

Commit the plan and push the branch:

```bash
git add docs/pr/${ISSUE}-${SCOPE_SLUG}/plan.md
git commit -m "<title> plan v1 (DRAFT)" -m "<body explaining scope and risk>"
git push -u origin refactor/${ISSUE}-${SCOPE_SLUG}
```

## Step 3: Dispatch Codex + Gemini in parallel

Use the **Agent** tool for Codex (subagent_type:
`codex:codex-rescue`) and the **Bash** tool to dispatch Gemini
directly. Both run in the background.

### Codex prompt template

```
node "/home/ps/.claude/plugins/cache/openai-codex/codex/1.0.4/scripts/codex-companion.mjs" task --background "Adversarial PLAN review for #<ISSUE> Step 1 ... Plan doc at docs/pr/<ISSUE>-<SLUG>/plan.md (commit <SHA> on branch refactor/<ISSUE>-<SLUG>).

Repo: /home/ps/git/bpfrx/.claude/worktrees/<ISSUE>-<SLUG>

This is a PLAN review, NOT a code review. No code has been written.

Plan summary: <2-3 sentence summary>.

What to verify (be hostile — fail the plan if architecture is wrong):

1. Is the perf justification sound at absolute scale? <specific numbers>
2. <Concrete code-level questions tied to file:line>
3. Stale-handle / borrow-checker / lifetime hazards
4. Cross-packet state ordering
5. Public API regression
6. <Project-specific risks: HA sync, GC, kernel state>
7. Architectural mismatch vs #961 / #946 Phase 2

Verdict: PLAN-READY / PLAN-NEEDS-MINOR / PLAN-NEEDS-MAJOR / PLAN-KILL. PLAN-KILL is appropriate if the architectural premise is wrong. Be hostile."
```

### Gemini prompt template

**Always pass `--model pro-3` (gemini-3-pro-preview).** The companion's
default is `gemini-2.5-flash`. On the refactor stream this project has
been driving (#946, #964, #959, #925), Flash repeatedly produced
verdicts that contradicted itself round-over-round, hallucinated
files/symbols that did not exist in the diff, or rubber-stamped
plans that Codex flagged as architecturally wrong. Pro 3 is the
right tier for adversarial plan + code review here; the Flash latency
saving is not worth the signal degradation when the methodology
hinges on whether one reviewer catches what the other misses.

```bash
node "/home/ps/.claude/plugins/cache/abiswas97-gemini/gemini/1.0.1/scripts/gemini-companion.mjs" task --background --model pro-3 "$(cat <<'PROMPT'
Adversarial PLAN review for #<ISSUE> Step 1 ...

Prime context: you are an expert in HPC networking, OS, data structures, JIT, CPU design, networking protocols. The codebase is xpf, an eBPF-based firewall with a userspace AF_XDP dataplane in Rust.

Plan doc to review: /home/ps/git/bpfrx/.claude/worktrees/<ISSUE>-<SLUG>/docs/pr/<ISSUE>-<SLUG>/plan.md (commit <SHA>).

[Same questions as Codex — request both reviewers verify independently.]

Verdict: PLAN-READY / PLAN-NEEDS-MINOR / PLAN-NEEDS-MAJOR / PLAN-KILL. PLAN-KILL is the right call if the perf gain is too small to justify the churn.
PROMPT
)"
```

After dispatch, **ScheduleWakeup with delaySeconds=300** and
return control. When you wake, fetch both verdicts.

## Step 4: Iterate plan-review until both reviewers agree

For each reviewer round:

```bash
# Codex
node /home/ps/.claude/plugins/cache/openai-codex/codex/1.0.4/scripts/codex-companion.mjs result <task-id>
# Gemini
node /home/ps/.claude/plugins/cache/abiswas97-gemini/gemini/1.0.1/scripts/gemini-companion.mjs result <task-id>
```

Outcomes:

- **Both PLAN-KILL** → stop. Update plan.md to record the
  KILLED status with both reviewer findings preserved verbatim.
  Comment on the issue with the analysis. Do NOT open a PR.
- **One PLAN-KILL, one not** → iterate the plan to address the
  KILL findings. May converge on KILL after another round.
- **Both PLAN-NEEDS-MAJOR / NEEDS-MINOR** → revise plan,
  push, re-dispatch.
- **Both PLAN-READY (or NEEDS-MINOR with all minor fixed)** →
  proceed to Step 5.

Don't lower the bar. The methodology only works if the kill
verdict is taken seriously.

## Step 5: Implement

Pure code motion is preferred when possible — it has no
architectural premise to fail. For data-structure or
control-flow changes, follow the plan exactly; if the
implementation reveals a deviation from the plan, **stop and
revise the plan** before continuing.

```bash
# After every meaningful change:
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo build 2>&1 | tail -5
```

## Step 6: Test

All gates, in order:

```bash
# Cargo full suite
TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release 2>&1 | tail -3

# 5x flake check on the most affected named test
for i in 1 2 3 4 5; do
  TMPDIR=/dev/shm CARGO_TARGET_DIR=/dev/shm/cargo cargo test --release <NAMED_TEST> 2>&1 | grep "test result" | tail -1
done

# Go suite
GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go test ./... 2>&1 | grep -v "^ok\|^?" | tail

# Deploy
export BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env
./test/incus/cluster-setup.sh deploy all

# === Pass A: CoS DISABLED (best-effort only) ===
# Catches regressions in the unshaped fast path. iperf-a default 5201
# falls through to best-effort.
#
# Tear down the entire CoS fixture, not just `class-of-service`. The
# cos-iperf fixture (`test/incus/cos-iperf-config.set`) also installs
# `firewall family inet/inet6 filter bandwidth-output` and binds it as
# the unit-80 output filter. Deleting only `class-of-service` while
# those bindings still reference its forwarding classes makes the
# commit fail validation. Junos-style candidate config means the live
# config stays unchanged on commit failure (no half-broken state on
# the wire) — but the silent failure mode is what hurts: CoS is still
# enabled, Pass A is invalid, and the smoke matrix reports clean
# numbers for what's effectively still Pass B. Use the fixture-aligned
# delete paths (mirrored from the top of `cos-iperf-config.set`):
#   - `firewall family inet|inet6 filter bandwidth-output`
#   - `interfaces reth0 unit 80 family inet|inet6 filter output`
# Apply atomically with `commit check` first so we never end up in a
# half-broken state. RG-0-primary-only.
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- rm -f /tmp/cos-iperf-sets.set"
# Don't pipe `cli` through `tail`/`head` here — that masks the cli exit
# status (pipeline returns `tail`'s status) and would silently swallow
# `commit check` / `commit` failures, leaving CoS partially attached
# while Pass A claims "CoS off". Use `set -o pipefail` if you must
# pipe; the simpler option below keeps full output visible and exits
# non-zero if the commit fails.
sg incus-admin -c "incus exec loss:xpf-userspace-fw0 -- bash -c 'set -e; /usr/local/sbin/cli <<CLI
configure
delete class-of-service
delete firewall family inet filter bandwidth-output
delete interfaces reth0 unit 80 family inet filter output
delete firewall family inet6 filter bandwidth-output
delete interfaces reth0 unit 80 family inet6 filter output
commit check
commit and-quit
exit
CLI
'" || { echo "Pass A teardown failed — aborting smoke matrix"; exit 1; }

# Note on grep targets: iperf3 reports the `Retr` (retransmit) column
# on the sender summary line for both push and reverse runs (for
# multi-stream `-P N` runs that's `[SUM] ... sender`; for single-stream
# runs it's `[ 5] ... sender`). We always grep the sender line — for
# `-R` runs the sender is the iperf3 server pushing data and Retr
# lives on its summary. Grepping `receiver` would show throughput but
# hide retrans entirely.
#
# These greps are VISIBILITY FILTERS, not programmatic gates: they
# expose the Retr column to the operator's eye so the "0 retrans"
# pass criterion (below) can be confirmed by reading the captured
# output. They do NOT fail on non-zero retrans by themselves. The
# smoke harness is doc-style — verify by inspection.
#
# CI integration note: if you wire this into a non-interactive
# runner, do BOTH of the following so failures surface:
#   1. `set -o pipefail` so a non-zero exit on either side of the
#      pipe propagates (the iperf3 binary itself returning non-zero
#      on connection failure no longer gets masked by `grep`).
#   2. Add explicit retrans-zero parsing. The `Retr` column on a
#      sender summary is the token immediately before the trailing
#      `sender` literal — robust parse:
#        awk '/sender/ { for (i=1;i<=NF;i++) if ($i=="sender") print $(i-1) }'
#      Field count varies between `[SUM]` (multi-stream) and `[ N]`
#      (single-stream) lines so a fixed `$N` index is fragile;
#      anchoring on the `sender` word avoids that.
set -o pipefail
echo "=== Pass A — CoS disabled, v4+v6 × push+reverse ==="
# Targets named explicitly to avoid colon-delimited packing (IPv6
# addresses contain colons, which makes any `${var%%:*}`-style split
# easy to misread even though bash semantics are correct). Use -F
# fixed-string grep so the dots in interval/timestamp tokens are
# matched literally rather than as regex wildcards.
declare -A TARGETS=(
  [v4]="172.16.80.200"
  [v6]="2001:559:8585:80::200"
)
# Filter strategy: don't pin the interval string ("0.00-5.00") — iperf3
# timing drift can print "0.00-5.01" or similar, which would falsely
# trigger the failure path. Filter on `sender` (every run prints exactly
# one summary sender line per stream, plus one `[SUM] ... sender` for
# `-P N`) and pick the last match. For multi-stream we further filter
# on the literal `[SUM]` to skip the per-stream sender lines.
for fam in v4 v6; do
  tgt=${TARGETS[$fam]}
  echo -n "$fam push: "; sg incus-admin -c "incus exec loss:cluster-userspace-host -- iperf3 -c $tgt -t 5 -p 5201"    2>&1 | grep -F -- "sender" | tail -1 || { echo "NO SENDER LINE — iperf3 failed"; exit 1; }
  echo -n "$fam rev:  "; sg incus-admin -c "incus exec loss:cluster-userspace-host -- iperf3 -c $tgt -t 5 -p 5201 -R" 2>&1 | grep -F -- "sender" | tail -1 || { echo "NO SENDER LINE — iperf3 failed"; exit 1; }
done

# Multi-stream reverse-mode reproducer (canonical TX-path regression
# catcher). A reverse cap with healthy push throughput is a TX-path
# regression. Pick the last `[SUM] ... sender` line so the Retr column
# stays visible without the brittle interval-string match.
echo "=== Pass A — 12-stream reverse reproducer (CoS disabled) ==="
sg incus-admin -c "incus exec loss:cluster-userspace-host -- iperf3 -c 172.16.80.200 -P 12 -t 10 -p 5201 -R"       2>&1 | grep -F -- "[SUM]" | grep -F -- "sender" | tail -1 || { echo "NO SUM SENDER LINE — iperf3 failed"; exit 1; }
sg incus-admin -c "incus exec loss:cluster-userspace-host -- iperf3 -c 2001:559:8585:80::200 -P 12 -t 10 -p 5201 -R" 2>&1 | grep -F -- "[SUM]" | grep -F -- "sender" | tail -1 || { echo "NO SUM SENDER LINE — iperf3 failed"; exit 1; }

# === Pass B: CoS ENABLED ===
sg incus-admin -c "./test/incus/apply-cos-config.sh loss:xpf-userspace-fw0"

# Per-class CoS smoke — v4+v6 × push+reverse × 6 ports = 24 measurements
# Same `sender` grep convention so retrans is visible for every cell.
echo "=== Pass B — Per-class CoS smoke ==="
# Same fixed-string + named-array shape as Pass A — port-class pairs
# in a `:`-packed string would be safe, but the iperf-class names use
# `-` not `:` and TARGETS[] is already in scope, so reuse it.
declare -A PORT_CLASS=(
  [5201]="iperf-a" [5202]="iperf-b" [5203]="iperf-c"
  [5204]="iperf-d" [5205]="iperf-e" [5206]="iperf-f"
)
for port in 5201 5202 5203 5204 5205 5206; do
  cls=${PORT_CLASS[$port]}
  echo "--- $port $cls ---"
  for fam in v4 v6; do
    tgt=${TARGETS[$fam]}
    echo -n "$fam push: "; sg incus-admin -c "incus exec loss:cluster-userspace-host -- iperf3 -c $tgt -t 5 -p $port"    2>&1 | grep -F -- "sender" | tail -1 || { echo "NO SENDER LINE — iperf3 failed"; exit 1; }
    echo -n "$fam rev:  "; sg incus-admin -c "incus exec loss:cluster-userspace-host -- iperf3 -c $tgt -t 5 -p $port -R" 2>&1 | grep -F -- "sender" | tail -1 || { echo "NO SENDER LINE — iperf3 failed"; exit 1; }
  done
done
```

**Required pass criteria:**
- Pass A (CoS disabled):
  - **Single-stream baselines** (4 cells, v4/v6 × push/rev): connectivity
    confirmed and **0 retrans**. *Single-stream throughput is NOT held to
    line rate — on this lab it caps at ~6-7 Gbps per flow due to per-CPU
    AF_XDP processing limits, which is normal.*
  - **Multi-stream `-P 12 -R` reproducers** (2 cells, v4 + v6): **line
    rate with 0 retrans.** This is where the line-rate gate lives.
    *A reverse cap here with healthy push is a TX-path regression —
    block on this.*
- Pass B (CoS enabled): all 24 per-class measurements pass with 0 retrans
  *for unshaped classes*. Shaped classes (e.g. iperf-a at 1 Gb/s) should
  hit their shape rate cleanly with ECN marks but no buffer drops.

## Step 7: Open PR

```bash
git add -A
git commit -m "<#ISSUE Step N: title>" -m "<body explaining scope, methodology rounds, smoke results>"
git push

gh pr create --title "<#ISSUE Step N: title>" --body "$(cat <<'EOF'
## Summary
<2-3 sentence what changed and why>

## Plan + adversarial review

Plan doc: docs/pr/<ISSUE>-<SLUG>/plan.md

- Codex round-N: PLAN-READY (task ID <X>)
- Gemini round-N: PLAN-READY (task ID <Y>)

## Test plan

- [x] cargo build clean
- [x] cargo test --release: N/N pass
- [x] <named-test> 5/5 flake check
- [x] Go suite: 30 packages pass
- [x] Deploy on loss userspace cluster
- [x] **Pass A — CoS disabled** (best-effort fast path)
  - [x] v4 push: <Mbps>, <retrans> retrans against 172.16.80.200
  - [x] v4 reverse (`-R`): <Mbps>, <retrans> retrans
  - [x] v6 push: <Mbps>, <retrans> retrans against 2001:559:8585:80::200
  - [x] v6 reverse (`-R`): <Mbps>, <retrans> retrans
  - [x] v4 multi-stream reverse: `iperf3 -P 12 -t 10 -R` — line rate, 0 retrans
  - [x] v6 multi-stream reverse: `iperf3 -P 12 -t 10 -R` — line rate, 0 retrans
- [x] **Pass B — CoS enabled** (per-class shaper + classifier)
  - [x] Per-class CoS smoke (5201-5206) v4+v6 push+reverse — all 24 measurements pass
  - [x] Shaped classes hit configured rate cleanly with ECN marks but no buffer drops

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"

gh pr edit <PR> --add-reviewer Copilot
```

After PR creation, post a comment with the per-class CoS smoke
table.

## Step 8: Wait for Copilot, dispatch Codex + Gemini code review

Poll until Copilot's review lands:

```bash
gh pr view <PR> --json reviews
gh api repos/psaab/xpf/pulls/<PR>/comments
```

ScheduleWakeup with 300s and check on next wake.

In parallel, dispatch Codex hostile code review and Gemini
adversarial code review on the PR commit.

```
# Codex hostile review
Hostile code review of PR #<PR> (#<ISSUE> Step N: <title>).
Repo: /home/ps/git/bpfrx/.claude/worktrees/<ISSUE>-<SLUG>
Branch: refactor/<ISSUE>-<SLUG>
Base: master (commit <BASE>)
Head: commit <HEAD>

What changed: <2-3 sentence summary>

What to verify:
1. Pure code motion claim verified by walking <files> and
   confirming side-effect ordering preserved.
2. Lifetime / borrow-checker shape clean.
3. Cross-packet state ordering preserved.
4. <Specific risk areas from plan>.
5. Smoke results are real.

Verdict format: MERGE-READY / MERGE-NEEDS-MINOR / MERGE-NEEDS-MAJOR.
```

## Step 9: Merge once all three agree

Required before merge:

- **Copilot** has posted a review (COMMENTED is fine; ensure
  every inline comment is addressed in a follow-up commit).
- **Codex** has returned MERGE-READY or MERGE-NEEDS-MINOR with
  every minor finding addressed.
- **Gemini** has returned MERGE-READY or MERGE-NEEDS-MINOR with
  every minor finding addressed.

If any of the three returns NEEDS-MAJOR, address the findings,
push a fix commit, re-dispatch reviewers (and re-request
Copilot via `gh pr edit --add-reviewer Copilot`), wait for
re-review, then re-merge-check.

```bash
gh pr merge <PR> --squash --auto
# or `--squash` directly if --auto isn't enabled
```

After merge, save findings to memory if anything non-obvious
came up:

- File: `/home/ps/.claude/projects/-home-ps-git-bpfrx/memory/project_<ISSUE>_<step>_<outcome>.md`
- Index entry: append one line to `MEMORY.md`.

## Anti-patterns this skill prevents

- **Shipping without plan review.** Avoided by Step 3 gating.
- **Pushing through PLAN-KILL.** Avoided by treating PLAN-KILL
  as a real outcome that ends the work.
- **Best-effort-only smoke.** Per-class CoS smoke catches
  classifier/policer regressions that port 5201 misses.
- **Skipping Copilot.** Step 8 requires waiting; Step 9
  requires Copilot in the agreement set.
- **Dismissing test failures as flakes.** Step 6's 5x flake
  check is non-negotiable.
- **#961 / #946 Phase 2 architectural mismatch.** Step 2's
  risk-assessment table forces explicit consideration; Step 3's
  reviewer prompts ask each reviewer to consider it.

## When to NOT use this skill

- **Pure documentation fixes** — no code change, no need for
  reviewer agreement. Just push and merge.
- **Single-line bug fixes** with obvious correctness — open a
  PR, request Copilot, merge after Copilot review. The full
  Codex+Gemini plan-review cycle is overkill.
- **Hot fixes during outage** — speed > rigor. Use a different
  process.

This skill is for **non-trivial refactors** where the
architectural premise itself needs validation before code lands.
